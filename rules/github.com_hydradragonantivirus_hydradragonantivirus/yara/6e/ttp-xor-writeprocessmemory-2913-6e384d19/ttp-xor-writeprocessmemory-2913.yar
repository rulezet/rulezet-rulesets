rule TTP_XOR_WriteProcessMemory_2913 {
  strings:
    $key_2913 = { 7e 61 [2] 4c 43 [2] 4a 76 [2] 64 76 [2] 5b 6a }

  condition:
    any of them
}