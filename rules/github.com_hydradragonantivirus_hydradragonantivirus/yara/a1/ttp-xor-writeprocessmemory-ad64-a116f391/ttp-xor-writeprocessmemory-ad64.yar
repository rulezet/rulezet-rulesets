rule TTP_XOR_WriteProcessMemory_ad64 {
  strings:
    $key_ad64 = { fa 16 [2] c8 34 [2] ce 01 [2] e0 01 [2] df 1d }

  condition:
    any of them
}