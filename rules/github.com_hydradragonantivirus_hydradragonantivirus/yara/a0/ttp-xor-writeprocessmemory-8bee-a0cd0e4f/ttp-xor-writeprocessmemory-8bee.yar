rule TTP_XOR_WriteProcessMemory_8bee {
  strings:
    $key_8bee = { dc 9c [2] ee be [2] e8 8b [2] c6 8b [2] f9 97 }

  condition:
    any of them
}