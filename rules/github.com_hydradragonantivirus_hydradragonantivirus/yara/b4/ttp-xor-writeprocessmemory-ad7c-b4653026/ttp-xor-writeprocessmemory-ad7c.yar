rule TTP_XOR_WriteProcessMemory_ad7c {
  strings:
    $key_ad7c = { fa 0e [2] c8 2c [2] ce 19 [2] e0 19 [2] df 05 }

  condition:
    any of them
}