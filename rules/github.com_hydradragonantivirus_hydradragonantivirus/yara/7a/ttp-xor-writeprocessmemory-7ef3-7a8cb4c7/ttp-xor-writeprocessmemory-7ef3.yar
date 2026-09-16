rule TTP_XOR_WriteProcessMemory_7ef3 {
  strings:
    $key_7ef3 = { 29 81 [2] 1b a3 [2] 1d 96 [2] 33 96 [2] 0c 8a }

  condition:
    any of them
}