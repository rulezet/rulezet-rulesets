rule TTP_XOR_WriteProcessMemory_0220 {
  strings:
    $key_0220 = { 55 52 [2] 67 70 [2] 61 45 [2] 4f 45 [2] 70 59 }

  condition:
    any of them
}