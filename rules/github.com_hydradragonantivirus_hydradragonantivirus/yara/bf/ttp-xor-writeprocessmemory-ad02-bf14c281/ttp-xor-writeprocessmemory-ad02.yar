rule TTP_XOR_WriteProcessMemory_ad02 {
  strings:
    $key_ad02 = { fa 70 [2] c8 52 [2] ce 67 [2] e0 67 [2] df 7b }

  condition:
    any of them
}