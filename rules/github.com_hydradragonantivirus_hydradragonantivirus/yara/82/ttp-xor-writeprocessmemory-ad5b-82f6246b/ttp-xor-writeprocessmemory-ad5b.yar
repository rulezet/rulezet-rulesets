rule TTP_XOR_WriteProcessMemory_ad5b {
  strings:
    $key_ad5b = { fa 29 [2] c8 0b [2] ce 3e [2] e0 3e [2] df 22 }

  condition:
    any of them
}