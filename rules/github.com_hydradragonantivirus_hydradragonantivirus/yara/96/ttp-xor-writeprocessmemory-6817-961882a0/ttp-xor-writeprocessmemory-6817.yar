rule TTP_XOR_WriteProcessMemory_6817 {
  strings:
    $key_6817 = { 3f 65 [2] 0d 47 [2] 0b 72 [2] 25 72 [2] 1a 6e }

  condition:
    any of them
}