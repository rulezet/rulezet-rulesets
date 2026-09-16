rule TTP_XOR_WriteProcessMemory_1a20 {
  strings:
    $key_1a20 = { 4d 52 [2] 7f 70 [2] 79 45 [2] 57 45 [2] 68 59 }

  condition:
    any of them
}