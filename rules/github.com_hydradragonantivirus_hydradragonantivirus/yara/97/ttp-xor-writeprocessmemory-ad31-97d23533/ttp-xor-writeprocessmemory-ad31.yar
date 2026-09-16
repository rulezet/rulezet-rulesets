rule TTP_XOR_WriteProcessMemory_ad31 {
  strings:
    $key_ad31 = { fa 43 [2] c8 61 [2] ce 54 [2] e0 54 [2] df 48 }

  condition:
    any of them
}