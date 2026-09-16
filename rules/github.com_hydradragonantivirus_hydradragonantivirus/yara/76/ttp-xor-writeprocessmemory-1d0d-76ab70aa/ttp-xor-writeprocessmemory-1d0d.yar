rule TTP_XOR_WriteProcessMemory_1d0d {
  strings:
    $key_1d0d = { 4a 7f [2] 78 5d [2] 7e 68 [2] 50 68 [2] 6f 74 }

  condition:
    any of them
}