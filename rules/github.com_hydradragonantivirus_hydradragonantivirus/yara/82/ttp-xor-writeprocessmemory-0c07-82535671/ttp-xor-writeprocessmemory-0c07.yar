rule TTP_XOR_WriteProcessMemory_0c07 {
  strings:
    $key_0c07 = { 5b 75 [2] 69 57 [2] 6f 62 [2] 41 62 [2] 7e 7e }

  condition:
    any of them
}