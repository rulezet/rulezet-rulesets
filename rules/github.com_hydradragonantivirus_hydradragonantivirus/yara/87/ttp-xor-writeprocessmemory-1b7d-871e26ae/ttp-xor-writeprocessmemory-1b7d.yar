rule TTP_XOR_WriteProcessMemory_1b7d {
  strings:
    $key_1b7d = { 4c 0f [2] 7e 2d [2] 78 18 [2] 56 18 [2] 69 04 }

  condition:
    any of them
}