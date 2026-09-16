rule TTP_XOR_WriteProcessMemory_ad17 {
  strings:
    $key_ad17 = { fa 65 [2] c8 47 [2] ce 72 [2] e0 72 [2] df 6e }

  condition:
    any of them
}