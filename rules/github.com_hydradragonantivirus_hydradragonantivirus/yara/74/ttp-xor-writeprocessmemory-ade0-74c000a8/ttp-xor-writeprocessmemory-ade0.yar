rule TTP_XOR_WriteProcessMemory_ade0 {
  strings:
    $key_ade0 = { fa 92 [2] c8 b0 [2] ce 85 [2] e0 85 [2] df 99 }

  condition:
    any of them
}