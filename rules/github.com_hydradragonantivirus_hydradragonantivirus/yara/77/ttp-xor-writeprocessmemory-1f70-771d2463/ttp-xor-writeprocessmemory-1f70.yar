rule TTP_XOR_WriteProcessMemory_1f70 {
  strings:
    $key_1f70 = { 48 02 [2] 7a 20 [2] 7c 15 [2] 52 15 [2] 6d 09 }

  condition:
    any of them
}