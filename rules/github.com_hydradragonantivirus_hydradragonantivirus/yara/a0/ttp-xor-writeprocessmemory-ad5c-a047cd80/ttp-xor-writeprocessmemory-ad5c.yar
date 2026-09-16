rule TTP_XOR_WriteProcessMemory_ad5c {
  strings:
    $key_ad5c = { fa 2e [2] c8 0c [2] ce 39 [2] e0 39 [2] df 25 }

  condition:
    any of them
}