rule TTP_XOR_WriteProcessMemory_ef83 {
  strings:
    $key_ef83 = { b8 f1 [2] 8a d3 [2] 8c e6 [2] a2 e6 [2] 9d fa }

  condition:
    any of them
}