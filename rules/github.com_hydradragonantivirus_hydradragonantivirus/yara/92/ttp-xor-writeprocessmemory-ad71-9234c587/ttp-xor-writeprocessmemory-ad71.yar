rule TTP_XOR_WriteProcessMemory_ad71 {
  strings:
    $key_ad71 = { fa 03 [2] c8 21 [2] ce 14 [2] e0 14 [2] df 08 }

  condition:
    any of them
}