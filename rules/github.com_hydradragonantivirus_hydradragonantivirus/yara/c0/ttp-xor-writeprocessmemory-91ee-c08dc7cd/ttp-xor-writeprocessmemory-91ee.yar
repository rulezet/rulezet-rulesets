rule TTP_XOR_WriteProcessMemory_91ee {
  strings:
    $key_91ee = { c6 9c [2] f4 be [2] f2 8b [2] dc 8b [2] e3 97 }

  condition:
    any of them
}