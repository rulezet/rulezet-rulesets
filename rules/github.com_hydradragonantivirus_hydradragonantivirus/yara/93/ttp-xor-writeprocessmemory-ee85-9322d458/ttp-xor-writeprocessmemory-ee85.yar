rule TTP_XOR_WriteProcessMemory_ee85 {
  strings:
    $key_ee85 = { b9 f7 [2] 8b d5 [2] 8d e0 [2] a3 e0 [2] 9c fc }

  condition:
    any of them
}