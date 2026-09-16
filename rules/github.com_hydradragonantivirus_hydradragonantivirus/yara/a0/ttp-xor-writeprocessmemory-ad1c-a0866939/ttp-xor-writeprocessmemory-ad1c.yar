rule TTP_XOR_WriteProcessMemory_ad1c {
  strings:
    $key_ad1c = { fa 6e [2] c8 4c [2] ce 79 [2] e0 79 [2] df 65 }

  condition:
    any of them
}