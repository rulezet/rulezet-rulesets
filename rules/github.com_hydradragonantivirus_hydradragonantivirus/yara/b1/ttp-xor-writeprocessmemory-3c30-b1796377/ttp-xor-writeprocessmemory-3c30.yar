rule TTP_XOR_WriteProcessMemory_3c30 {
  strings:
    $key_3c30 = { 6b 42 [2] 59 60 [2] 5f 55 [2] 71 55 [2] 4e 49 }

  condition:
    any of them
}