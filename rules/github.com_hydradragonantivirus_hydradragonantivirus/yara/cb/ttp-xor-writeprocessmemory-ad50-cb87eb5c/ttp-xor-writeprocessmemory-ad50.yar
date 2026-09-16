rule TTP_XOR_WriteProcessMemory_ad50 {
  strings:
    $key_ad50 = { fa 22 [2] c8 00 [2] ce 35 [2] e0 35 [2] df 29 }

  condition:
    any of them
}