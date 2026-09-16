rule TTP_XOR_WriteProcessMemory_2a35 {
  strings:
    $key_2a35 = { 7d 47 [2] 4f 65 [2] 49 50 [2] 67 50 [2] 58 4c }

  condition:
    any of them
}