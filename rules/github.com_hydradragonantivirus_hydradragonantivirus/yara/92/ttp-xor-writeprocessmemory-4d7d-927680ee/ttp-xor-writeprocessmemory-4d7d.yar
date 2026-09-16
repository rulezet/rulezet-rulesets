rule TTP_XOR_WriteProcessMemory_4d7d {
  strings:
    $key_4d7d = { 1a 0f [2] 28 2d [2] 2e 18 [2] 00 18 [2] 3f 04 }

  condition:
    any of them
}