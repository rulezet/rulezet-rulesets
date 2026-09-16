rule TTP_XOR_WriteProcessMemory_ad75 {
  strings:
    $key_ad75 = { fa 07 [2] c8 25 [2] ce 10 [2] e0 10 [2] df 0c }

  condition:
    any of them
}