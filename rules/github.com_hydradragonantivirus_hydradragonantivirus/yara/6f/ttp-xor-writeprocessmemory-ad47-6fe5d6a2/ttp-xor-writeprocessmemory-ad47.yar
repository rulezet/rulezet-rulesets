rule TTP_XOR_WriteProcessMemory_ad47 {
  strings:
    $key_ad47 = { fa 35 [2] c8 17 [2] ce 22 [2] e0 22 [2] df 3e }

  condition:
    any of them
}