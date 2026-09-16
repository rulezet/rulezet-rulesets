rule TTP_XOR_WriteProcessMemory_ad4b {
  strings:
    $key_ad4b = { fa 39 [2] c8 1b [2] ce 2e [2] e0 2e [2] df 32 }

  condition:
    any of them
}