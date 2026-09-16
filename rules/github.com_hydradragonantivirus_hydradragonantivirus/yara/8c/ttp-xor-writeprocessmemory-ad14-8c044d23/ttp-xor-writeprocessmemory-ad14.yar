rule TTP_XOR_WriteProcessMemory_ad14 {
  strings:
    $key_ad14 = { fa 66 [2] c8 44 [2] ce 71 [2] e0 71 [2] df 6d }

  condition:
    any of them
}