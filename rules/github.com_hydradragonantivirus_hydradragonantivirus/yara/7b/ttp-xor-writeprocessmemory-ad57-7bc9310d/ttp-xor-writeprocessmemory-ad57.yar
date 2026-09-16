rule TTP_XOR_WriteProcessMemory_ad57 {
  strings:
    $key_ad57 = { fa 25 [2] c8 07 [2] ce 32 [2] e0 32 [2] df 2e }

  condition:
    any of them
}