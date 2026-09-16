rule TTP_XOR_WriteProcessMemory_61f9 {
  strings:
    $key_61f9 = { 36 8b [2] 04 a9 [2] 02 9c [2] 2c 9c [2] 13 80 }

  condition:
    any of them
}