rule TTP_XOR_WriteProcessMemory_ad5d {
  strings:
    $key_ad5d = { fa 2f [2] c8 0d [2] ce 38 [2] e0 38 [2] df 24 }

  condition:
    any of them
}