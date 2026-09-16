rule TTP_XOR_WriteProcessMemory_287c {
  strings:
    $key_287c = { 7f 0e [2] 4d 2c [2] 4b 19 [2] 65 19 [2] 5a 05 }

  condition:
    any of them
}