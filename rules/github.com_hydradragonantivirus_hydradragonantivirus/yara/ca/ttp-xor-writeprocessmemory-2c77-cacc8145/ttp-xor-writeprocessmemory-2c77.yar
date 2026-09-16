rule TTP_XOR_WriteProcessMemory_2c77 {
  strings:
    $key_2c77 = { 7b 05 [2] 49 27 [2] 4f 12 [2] 61 12 [2] 5e 0e }

  condition:
    any of them
}