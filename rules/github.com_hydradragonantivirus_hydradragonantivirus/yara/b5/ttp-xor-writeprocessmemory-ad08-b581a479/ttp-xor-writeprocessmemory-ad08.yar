rule TTP_XOR_WriteProcessMemory_ad08 {
  strings:
    $key_ad08 = { fa 7a [2] c8 58 [2] ce 6d [2] e0 6d [2] df 71 }

  condition:
    any of them
}