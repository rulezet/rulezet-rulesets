rule TTP_XOR_WriteProcessMemory_ad0c {
  strings:
    $key_ad0c = { fa 7e [2] c8 5c [2] ce 69 [2] e0 69 [2] df 75 }

  condition:
    any of them
}