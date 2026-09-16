rule TTP_XOR_WriteProcessMemory_0c43 {
  strings:
    $key_0c43 = { 5b 31 [2] 69 13 [2] 6f 26 [2] 41 26 [2] 7e 3a }

  condition:
    any of them
}