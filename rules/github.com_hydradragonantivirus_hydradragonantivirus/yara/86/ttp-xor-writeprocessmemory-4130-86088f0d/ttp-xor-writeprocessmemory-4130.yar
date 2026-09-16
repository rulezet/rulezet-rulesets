rule TTP_XOR_WriteProcessMemory_4130 {
  strings:
    $key_4130 = { 16 42 [2] 24 60 [2] 22 55 [2] 0c 55 [2] 33 49 }

  condition:
    any of them
}