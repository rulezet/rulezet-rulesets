rule TTP_XOR_WriteProcessMemory_1b0d {
  strings:
    $key_1b0d = { 4c 7f [2] 7e 5d [2] 78 68 [2] 56 68 [2] 69 74 }

  condition:
    any of them
}