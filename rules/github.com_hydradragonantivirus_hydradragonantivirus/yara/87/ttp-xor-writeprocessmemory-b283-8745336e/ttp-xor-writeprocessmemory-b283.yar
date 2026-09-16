rule TTP_XOR_WriteProcessMemory_b283 {
  strings:
    $key_b283 = { e5 f1 [2] d7 d3 [2] d1 e6 [2] ff e6 [2] c0 fa }

  condition:
    any of them
}