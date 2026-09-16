rule TTP_XOR_WriteProcessMemory_1b54 {
  strings:
    $key_1b54 = { 4c 26 [2] 7e 04 [2] 78 31 [2] 56 31 [2] 69 2d }

  condition:
    any of them
}