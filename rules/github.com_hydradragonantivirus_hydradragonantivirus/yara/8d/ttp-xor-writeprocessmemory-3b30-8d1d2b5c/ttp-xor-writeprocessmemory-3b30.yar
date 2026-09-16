rule TTP_XOR_WriteProcessMemory_3b30 {
  strings:
    $key_3b30 = { 6c 42 [2] 5e 60 [2] 58 55 [2] 76 55 [2] 49 49 }

  condition:
    any of them
}