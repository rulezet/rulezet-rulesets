rule TTP_XOR_WriteProcessMemory_ad59 {
  strings:
    $key_ad59 = { fa 2b [2] c8 09 [2] ce 3c [2] e0 3c [2] df 20 }

  condition:
    any of them
}