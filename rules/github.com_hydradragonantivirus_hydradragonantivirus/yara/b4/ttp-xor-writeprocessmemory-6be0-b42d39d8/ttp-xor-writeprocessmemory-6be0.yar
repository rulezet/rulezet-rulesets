rule TTP_XOR_WriteProcessMemory_6be0 {
  strings:
    $key_6be0 = { 3c 92 [2] 0e b0 [2] 08 85 [2] 26 85 [2] 19 99 }

  condition:
    any of them
}