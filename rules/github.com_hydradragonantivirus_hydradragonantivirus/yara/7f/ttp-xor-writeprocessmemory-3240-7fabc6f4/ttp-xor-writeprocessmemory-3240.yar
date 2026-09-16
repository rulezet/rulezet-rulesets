rule TTP_XOR_WriteProcessMemory_3240 {
  strings:
    $key_3240 = { 65 32 [2] 57 10 [2] 51 25 [2] 7f 25 [2] 40 39 }

  condition:
    any of them
}