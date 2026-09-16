rule TTP_XOR_WriteProcessMemory_e977 {
  strings:
    $key_e977 = { be 05 [2] 8c 27 [2] 8a 12 [2] a4 12 [2] 9b 0e }

  condition:
    any of them
}