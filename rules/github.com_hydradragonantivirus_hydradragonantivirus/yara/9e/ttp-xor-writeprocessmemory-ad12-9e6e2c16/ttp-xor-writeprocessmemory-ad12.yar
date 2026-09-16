rule TTP_XOR_WriteProcessMemory_ad12 {
  strings:
    $key_ad12 = { fa 60 [2] c8 42 [2] ce 77 [2] e0 77 [2] df 6b }

  condition:
    any of them
}