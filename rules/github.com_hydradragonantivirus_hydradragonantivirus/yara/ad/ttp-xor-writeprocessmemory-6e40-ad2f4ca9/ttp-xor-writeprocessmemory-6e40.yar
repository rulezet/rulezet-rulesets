rule TTP_XOR_WriteProcessMemory_6e40 {
  strings:
    $key_6e40 = { 39 32 [2] 0b 10 [2] 0d 25 [2] 23 25 [2] 1c 39 }

  condition:
    any of them
}