rule TTP_XOR_WriteProcessMemory_2c27 {
  strings:
    $key_2c27 = { 7b 55 [2] 49 77 [2] 4f 42 [2] 61 42 [2] 5e 5e }

  condition:
    any of them
}