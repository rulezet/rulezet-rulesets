rule TTP_XOR_WriteProcessMemory_ad09 {
  strings:
    $key_ad09 = { fa 7b [2] c8 59 [2] ce 6c [2] e0 6c [2] df 70 }

  condition:
    any of them
}