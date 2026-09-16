rule TTP_XOR_WriteProcessMemory_7f60 {
  strings:
    $key_7f60 = { 28 12 [2] 1a 30 [2] 1c 05 [2] 32 05 [2] 0d 19 }

  condition:
    any of them
}