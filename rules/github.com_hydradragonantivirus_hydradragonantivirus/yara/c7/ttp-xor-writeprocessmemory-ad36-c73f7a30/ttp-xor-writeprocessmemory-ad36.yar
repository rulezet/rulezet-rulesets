rule TTP_XOR_WriteProcessMemory_ad36 {
  strings:
    $key_ad36 = { fa 44 [2] c8 66 [2] ce 53 [2] e0 53 [2] df 4f }

  condition:
    any of them
}