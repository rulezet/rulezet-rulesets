rule TTP_XOR_WriteProcessMemory_0c02 {
  strings:
    $key_0c02 = { 5b 70 [2] 69 52 [2] 6f 67 [2] 41 67 [2] 7e 7b }

  condition:
    any of them
}