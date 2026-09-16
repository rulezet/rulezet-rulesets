rule TTP_XOR_WriteProcessMemory_4638 {
  strings:
    $key_4638 = { 11 4a [2] 23 68 [2] 25 5d [2] 0b 5d [2] 34 41 }

  condition:
    any of them
}