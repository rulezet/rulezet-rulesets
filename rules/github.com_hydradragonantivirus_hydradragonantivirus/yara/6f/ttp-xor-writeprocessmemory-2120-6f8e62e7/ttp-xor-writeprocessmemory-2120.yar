rule TTP_XOR_WriteProcessMemory_2120 {
  strings:
    $key_2120 = { 76 52 [2] 44 70 [2] 42 45 [2] 6c 45 [2] 53 59 }

  condition:
    any of them
}