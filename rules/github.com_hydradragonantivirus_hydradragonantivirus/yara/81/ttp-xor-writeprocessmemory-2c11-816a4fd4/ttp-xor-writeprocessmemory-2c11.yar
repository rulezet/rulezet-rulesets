rule TTP_XOR_WriteProcessMemory_2c11 {
  strings:
    $key_2c11 = { 7b 63 [2] 49 41 [2] 4f 74 [2] 61 74 [2] 5e 68 }

  condition:
    any of them
}