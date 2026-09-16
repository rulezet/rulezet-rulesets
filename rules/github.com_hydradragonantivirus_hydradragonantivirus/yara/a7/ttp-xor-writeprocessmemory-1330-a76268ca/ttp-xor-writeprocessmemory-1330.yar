rule TTP_XOR_WriteProcessMemory_1330 {
  strings:
    $key_1330 = { 44 42 [2] 76 60 [2] 70 55 [2] 5e 55 [2] 61 49 }

  condition:
    any of them
}