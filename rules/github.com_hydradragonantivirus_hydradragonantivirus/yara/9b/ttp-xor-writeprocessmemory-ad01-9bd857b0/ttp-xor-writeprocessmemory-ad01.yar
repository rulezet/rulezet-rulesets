rule TTP_XOR_WriteProcessMemory_ad01 {
  strings:
    $key_ad01 = { fa 73 [2] c8 51 [2] ce 64 [2] e0 64 [2] df 78 }

  condition:
    any of them
}