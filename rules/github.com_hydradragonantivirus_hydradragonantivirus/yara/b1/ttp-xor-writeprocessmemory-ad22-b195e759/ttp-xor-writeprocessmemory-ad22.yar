rule TTP_XOR_WriteProcessMemory_ad22 {
  strings:
    $key_ad22 = { fa 50 [2] c8 72 [2] ce 47 [2] e0 47 [2] df 5b }

  condition:
    any of them
}