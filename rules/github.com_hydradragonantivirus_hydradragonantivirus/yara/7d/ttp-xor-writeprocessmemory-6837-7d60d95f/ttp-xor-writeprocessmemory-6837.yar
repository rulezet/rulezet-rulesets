rule TTP_XOR_WriteProcessMemory_6837 {
  strings:
    $key_6837 = { 3f 45 [2] 0d 67 [2] 0b 52 [2] 25 52 [2] 1a 4e }

  condition:
    any of them
}