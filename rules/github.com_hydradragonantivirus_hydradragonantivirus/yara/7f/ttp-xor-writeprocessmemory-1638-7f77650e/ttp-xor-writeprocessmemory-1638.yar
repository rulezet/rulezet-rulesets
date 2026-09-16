rule TTP_XOR_WriteProcessMemory_1638 {
  strings:
    $key_1638 = { 41 4a [2] 73 68 [2] 75 5d [2] 5b 5d [2] 64 41 }

  condition:
    any of them
}