rule TTP_XOR_WriteProcessMemory_5b13 {
  strings:
    $key_5b13 = { 0c 61 [2] 3e 43 [2] 38 76 [2] 16 76 [2] 29 6a }

  condition:
    any of them
}