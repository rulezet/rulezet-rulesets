rule TTP_XOR_WriteProcessMemory_4170 {
  strings:
    $key_4170 = { 16 02 [2] 24 20 [2] 22 15 [2] 0c 15 [2] 33 09 }

  condition:
    any of them
}