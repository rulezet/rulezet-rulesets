rule TTP_XOR_WriteProcessMemory_ade6 {
  strings:
    $key_ade6 = { fa 94 [2] c8 b6 [2] ce 83 [2] e0 83 [2] df 9f }

  condition:
    any of them
}