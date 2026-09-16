rule TTP_XOR_WriteProcessMemory_ad72 {
  strings:
    $key_ad72 = { fa 00 [2] c8 22 [2] ce 17 [2] e0 17 [2] df 0b }

  condition:
    any of them
}