rule TTP_XOR_WriteProcessMemory_ad21 {
  strings:
    $key_ad21 = { fa 53 [2] c8 71 [2] ce 44 [2] e0 44 [2] df 58 }

  condition:
    any of them
}