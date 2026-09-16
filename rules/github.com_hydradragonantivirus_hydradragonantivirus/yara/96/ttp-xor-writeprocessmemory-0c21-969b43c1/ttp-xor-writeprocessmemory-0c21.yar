rule TTP_XOR_WriteProcessMemory_0c21 {
  strings:
    $key_0c21 = { 5b 53 [2] 69 71 [2] 6f 44 [2] 41 44 [2] 7e 58 }

  condition:
    any of them
}