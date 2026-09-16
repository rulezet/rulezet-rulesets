rule TTP_XOR_WriteProcessMemory_c466 {
  strings:
    $key_c466 = { 93 14 [2] a1 36 [2] a7 03 [2] 89 03 [2] b6 1f }

  condition:
    any of them
}