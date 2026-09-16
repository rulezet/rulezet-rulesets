rule TTP_XOR_WriteProcessMemory_1b74 {
  strings:
    $key_1b74 = { 4c 06 [2] 7e 24 [2] 78 11 [2] 56 11 [2] 69 0d }

  condition:
    any of them
}