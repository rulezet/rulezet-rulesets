rule TTP_XOR_WriteProcessMemory_c5b5 {
  strings:
    $key_c5b5 = { 92 c7 [2] a0 e5 [2] a6 d0 [2] 88 d0 [2] b7 cc }

  condition:
    any of them
}