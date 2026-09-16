rule TTP_XOR_WriteProcessMemory_8bef {
  strings:
    $key_8bef = { dc 9d [2] ee bf [2] e8 8a [2] c6 8a [2] f9 96 }

  condition:
    any of them
}