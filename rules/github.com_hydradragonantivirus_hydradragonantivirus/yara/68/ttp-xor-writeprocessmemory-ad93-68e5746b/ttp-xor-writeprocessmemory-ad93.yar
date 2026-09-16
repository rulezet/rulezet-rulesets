rule TTP_XOR_WriteProcessMemory_ad93 {
  strings:
    $key_ad93 = { fa e1 [2] c8 c3 [2] ce f6 [2] e0 f6 [2] df ea }

  condition:
    any of them
}