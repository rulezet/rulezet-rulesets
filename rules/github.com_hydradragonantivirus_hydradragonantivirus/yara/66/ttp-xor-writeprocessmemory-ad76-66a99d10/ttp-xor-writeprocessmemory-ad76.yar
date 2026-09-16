rule TTP_XOR_WriteProcessMemory_ad76 {
  strings:
    $key_ad76 = { fa 04 [2] c8 26 [2] ce 13 [2] e0 13 [2] df 0f }

  condition:
    any of them
}