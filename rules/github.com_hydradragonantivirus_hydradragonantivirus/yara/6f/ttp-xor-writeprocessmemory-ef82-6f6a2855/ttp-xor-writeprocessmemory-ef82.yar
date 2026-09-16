rule TTP_XOR_WriteProcessMemory_ef82 {
  strings:
    $key_ef82 = { b8 f0 [2] 8a d2 [2] 8c e7 [2] a2 e7 [2] 9d fb }

  condition:
    any of them
}