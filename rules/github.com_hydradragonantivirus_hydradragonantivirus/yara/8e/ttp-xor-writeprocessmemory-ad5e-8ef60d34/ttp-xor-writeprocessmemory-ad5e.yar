rule TTP_XOR_WriteProcessMemory_ad5e {
  strings:
    $key_ad5e = { fa 2c [2] c8 0e [2] ce 3b [2] e0 3b [2] df 27 }

  condition:
    any of them
}