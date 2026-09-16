rule TTP_XOR_WriteProcessMemory_ad1a {
  strings:
    $key_ad1a = { fa 68 [2] c8 4a [2] ce 7f [2] e0 7f [2] df 63 }

  condition:
    any of them
}