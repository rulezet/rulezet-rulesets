rule TTP_XOR_WriteProcessMemory_ad4a {
  strings:
    $key_ad4a = { fa 38 [2] c8 1a [2] ce 2f [2] e0 2f [2] df 33 }

  condition:
    any of them
}