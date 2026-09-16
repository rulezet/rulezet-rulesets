rule TTP_XOR_WriteProcessMemory_1b5d {
  strings:
    $key_1b5d = { 4c 2f [2] 7e 0d [2] 78 38 [2] 56 38 [2] 69 24 }

  condition:
    any of them
}