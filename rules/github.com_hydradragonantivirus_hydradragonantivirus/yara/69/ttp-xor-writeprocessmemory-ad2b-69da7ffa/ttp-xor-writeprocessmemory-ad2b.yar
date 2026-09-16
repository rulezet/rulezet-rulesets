rule TTP_XOR_WriteProcessMemory_ad2b {
  strings:
    $key_ad2b = { fa 59 [2] c8 7b [2] ce 4e [2] e0 4e [2] df 52 }

  condition:
    any of them
}