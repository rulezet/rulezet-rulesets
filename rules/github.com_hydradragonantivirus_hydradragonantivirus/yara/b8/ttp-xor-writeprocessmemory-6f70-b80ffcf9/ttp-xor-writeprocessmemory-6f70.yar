rule TTP_XOR_WriteProcessMemory_6f70 {
  strings:
    $key_6f70 = { 38 02 [2] 0a 20 [2] 0c 15 [2] 22 15 [2] 1d 09 }

  condition:
    any of them
}