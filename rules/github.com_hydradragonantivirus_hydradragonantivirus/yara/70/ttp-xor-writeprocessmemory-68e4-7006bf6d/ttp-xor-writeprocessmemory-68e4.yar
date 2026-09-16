rule TTP_XOR_WriteProcessMemory_68e4 {
  strings:
    $key_68e4 = { 3f 96 [2] 0d b4 [2] 0b 81 [2] 25 81 [2] 1a 9d }

  condition:
    any of them
}