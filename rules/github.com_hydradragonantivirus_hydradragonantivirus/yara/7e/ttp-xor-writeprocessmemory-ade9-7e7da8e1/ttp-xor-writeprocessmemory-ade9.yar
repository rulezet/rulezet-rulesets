rule TTP_XOR_WriteProcessMemory_ade9 {
  strings:
    $key_ade9 = { fa 9b [2] c8 b9 [2] ce 8c [2] e0 8c [2] df 90 }

  condition:
    any of them
}