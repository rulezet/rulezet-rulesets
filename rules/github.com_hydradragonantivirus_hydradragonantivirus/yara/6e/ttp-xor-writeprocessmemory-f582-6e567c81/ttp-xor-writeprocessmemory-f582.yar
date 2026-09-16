rule TTP_XOR_WriteProcessMemory_f582 {
  strings:
    $key_f582 = { a2 f0 [2] 90 d2 [2] 96 e7 [2] b8 e7 [2] 87 fb }

  condition:
    any of them
}