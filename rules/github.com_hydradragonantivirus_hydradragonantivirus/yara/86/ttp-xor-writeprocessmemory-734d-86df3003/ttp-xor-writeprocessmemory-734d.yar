rule TTP_XOR_WriteProcessMemory_734d {
  strings:
    $key_734d = { 24 3f [2] 16 1d [2] 10 28 [2] 3e 28 [2] 01 34 }

  condition:
    any of them
}