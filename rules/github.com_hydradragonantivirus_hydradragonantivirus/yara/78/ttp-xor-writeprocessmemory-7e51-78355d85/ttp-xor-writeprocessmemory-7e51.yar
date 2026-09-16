rule TTP_XOR_WriteProcessMemory_7e51 {
  strings:
    $key_7e51 = { 29 23 [2] 1b 01 [2] 1d 34 [2] 33 34 [2] 0c 28 }

  condition:
    any of them
}