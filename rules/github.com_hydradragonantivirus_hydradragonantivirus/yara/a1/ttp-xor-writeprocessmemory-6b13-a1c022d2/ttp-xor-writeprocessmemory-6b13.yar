rule TTP_XOR_WriteProcessMemory_6b13 {
  strings:
    $key_6b13 = { 3c 61 [2] 0e 43 [2] 08 76 [2] 26 76 [2] 19 6a }

  condition:
    any of them
}