rule TTP_XOR_WriteProcessMemory_0c13 {
  strings:
    $key_0c13 = { 5b 61 [2] 69 43 [2] 6f 76 [2] 41 76 [2] 7e 6a }

  condition:
    any of them
}