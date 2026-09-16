rule TTP_XOR_WriteProcessMemory_ad73 {
  strings:
    $key_ad73 = { fa 01 [2] c8 23 [2] ce 16 [2] e0 16 [2] df 0a }

  condition:
    any of them
}