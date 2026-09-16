rule TTP_XOR_WriteProcessMemory_6840 {
  strings:
    $key_6840 = { 3f 32 [2] 0d 10 [2] 0b 25 [2] 25 25 [2] 1a 39 }

  condition:
    any of them
}