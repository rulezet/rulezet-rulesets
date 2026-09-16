rule TTP_XOR_WriteProcessMemory_3578 {
  strings:
    $key_3578 = { 62 0a [2] 50 28 [2] 56 1d [2] 78 1d [2] 47 01 }

  condition:
    any of them
}