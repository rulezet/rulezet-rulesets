rule TTP_XOR_WriteProcessMemory_7738 {
  strings:
    $key_7738 = { 20 4a [2] 12 68 [2] 14 5d [2] 3a 5d [2] 05 41 }

  condition:
    any of them
}