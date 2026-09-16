rule TTP_XOR_WriteProcessMemory_7e13 {
  strings:
    $key_7e13 = { 29 61 [2] 1b 43 [2] 1d 76 [2] 33 76 [2] 0c 6a }

  condition:
    any of them
}