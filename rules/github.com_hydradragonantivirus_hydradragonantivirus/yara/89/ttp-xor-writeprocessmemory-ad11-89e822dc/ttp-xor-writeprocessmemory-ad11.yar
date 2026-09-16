rule TTP_XOR_WriteProcessMemory_ad11 {
  strings:
    $key_ad11 = { fa 63 [2] c8 41 [2] ce 74 [2] e0 74 [2] df 68 }

  condition:
    any of them
}