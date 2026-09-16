rule TTP_XOR_WriteProcessMemory_ad6b {
  strings:
    $key_ad6b = { fa 19 [2] c8 3b [2] ce 0e [2] e0 0e [2] df 12 }

  condition:
    any of them
}