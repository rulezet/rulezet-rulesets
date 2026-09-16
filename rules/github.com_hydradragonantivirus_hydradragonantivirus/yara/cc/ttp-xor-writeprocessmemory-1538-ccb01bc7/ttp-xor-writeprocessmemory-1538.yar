rule TTP_XOR_WriteProcessMemory_1538 {
  strings:
    $key_1538 = { 42 4a [2] 70 68 [2] 76 5d [2] 58 5d [2] 67 41 }

  condition:
    any of them
}