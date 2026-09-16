rule TTP_XOR_WriteProcessMemory_c303 {
  strings:
    $key_c303 = { 94 71 [2] a6 53 [2] a0 66 [2] 8e 66 [2] b1 7a }

  condition:
    any of them
}