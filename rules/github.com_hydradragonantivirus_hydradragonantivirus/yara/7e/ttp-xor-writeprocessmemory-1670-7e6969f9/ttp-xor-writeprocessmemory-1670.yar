rule TTP_XOR_WriteProcessMemory_1670 {
  strings:
    $key_1670 = { 41 02 [2] 73 20 [2] 75 15 [2] 5b 15 [2] 64 09 }

  condition:
    any of them
}