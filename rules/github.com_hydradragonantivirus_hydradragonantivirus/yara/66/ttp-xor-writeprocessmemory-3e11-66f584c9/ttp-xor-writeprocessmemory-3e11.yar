rule TTP_XOR_WriteProcessMemory_3e11 {
  strings:
    $key_3e11 = { 69 63 [2] 5b 41 [2] 5d 74 [2] 73 74 [2] 4c 68 }

  condition:
    any of them
}