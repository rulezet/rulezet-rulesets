rule TTP_XOR_WriteProcessMemory_2a20 {
  strings:
    $key_2a20 = { 7d 52 [2] 4f 70 [2] 49 45 [2] 67 45 [2] 58 59 }

  condition:
    any of them
}