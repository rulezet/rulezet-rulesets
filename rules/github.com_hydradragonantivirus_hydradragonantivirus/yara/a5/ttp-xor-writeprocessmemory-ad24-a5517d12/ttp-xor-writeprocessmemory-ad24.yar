rule TTP_XOR_WriteProcessMemory_ad24 {
  strings:
    $key_ad24 = { fa 56 [2] c8 74 [2] ce 41 [2] e0 41 [2] df 5d }

  condition:
    any of them
}