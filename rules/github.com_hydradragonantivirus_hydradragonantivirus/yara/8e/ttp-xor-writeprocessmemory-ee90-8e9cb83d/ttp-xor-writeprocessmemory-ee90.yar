rule TTP_XOR_WriteProcessMemory_ee90 {
  strings:
    $key_ee90 = { b9 e2 [2] 8b c0 [2] 8d f5 [2] a3 f5 [2] 9c e9 }

  condition:
    any of them
}