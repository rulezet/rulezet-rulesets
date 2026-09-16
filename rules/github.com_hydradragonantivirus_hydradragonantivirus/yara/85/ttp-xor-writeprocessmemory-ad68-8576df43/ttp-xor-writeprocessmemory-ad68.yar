rule TTP_XOR_WriteProcessMemory_ad68 {
  strings:
    $key_ad68 = { fa 1a [2] c8 38 [2] ce 0d [2] e0 0d [2] df 11 }

  condition:
    any of them
}