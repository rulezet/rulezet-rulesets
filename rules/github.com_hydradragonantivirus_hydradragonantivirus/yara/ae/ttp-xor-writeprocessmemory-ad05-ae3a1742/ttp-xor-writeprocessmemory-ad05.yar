rule TTP_XOR_WriteProcessMemory_ad05 {
  strings:
    $key_ad05 = { fa 77 [2] c8 55 [2] ce 60 [2] e0 60 [2] df 7c }

  condition:
    any of them
}