rule TTP_XOR_WriteProcessMemory_3e51 {
  strings:
    $key_3e51 = { 69 23 [2] 5b 01 [2] 5d 34 [2] 73 34 [2] 4c 28 }

  condition:
    any of them
}