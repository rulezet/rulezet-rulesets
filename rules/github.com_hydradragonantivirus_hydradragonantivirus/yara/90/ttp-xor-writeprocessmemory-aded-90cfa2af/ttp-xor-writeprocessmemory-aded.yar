rule TTP_XOR_WriteProcessMemory_aded {
  strings:
    $key_aded = { fa 9f [2] c8 bd [2] ce 88 [2] e0 88 [2] df 94 }

  condition:
    any of them
}