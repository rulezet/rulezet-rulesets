rule TTP_XOR_WriteProcessMemory_c518 {
  strings:
    $key_c518 = { 92 6a [2] a0 48 [2] a6 7d [2] 88 7d [2] b7 61 }

  condition:
    any of them
}