rule TTP_XOR_WriteProcessMemory_ad78 {
  strings:
    $key_ad78 = { fa 0a [2] c8 28 [2] ce 1d [2] e0 1d [2] df 01 }

  condition:
    any of them
}