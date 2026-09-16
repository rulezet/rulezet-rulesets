rule TTP_XOR_WriteProcessMemory_4120 {
  strings:
    $key_4120 = { 16 52 [2] 24 70 [2] 22 45 [2] 0c 45 [2] 33 59 }

  condition:
    any of them
}