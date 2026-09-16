rule TTP_XOR_WriteProcessMemory_0213 {
  strings:
    $key_0213 = { 55 61 [2] 67 43 [2] 61 76 [2] 4f 76 [2] 70 6a }

  condition:
    any of them
}