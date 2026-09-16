rule TTP_XOR_WriteProcessMemory_ad20 {
  strings:
    $key_ad20 = { fa 52 [2] c8 70 [2] ce 45 [2] e0 45 [2] df 59 }

  condition:
    any of them
}