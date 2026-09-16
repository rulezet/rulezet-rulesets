rule TTP_XOR_WriteProcessMemory_ad49 {
  strings:
    $key_ad49 = { fa 3b [2] c8 19 [2] ce 2c [2] e0 2c [2] df 30 }

  condition:
    any of them
}