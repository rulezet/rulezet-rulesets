rule TTP_XOR_WriteProcessMemory_ad40 {
  strings:
    $key_ad40 = { fa 32 [2] c8 10 [2] ce 25 [2] e0 25 [2] df 39 }

  condition:
    any of them
}