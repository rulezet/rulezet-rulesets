rule TTP_XOR_WriteProcessMemory_c837 {
  strings:
    $key_c837 = { 9f 45 [2] ad 67 [2] ab 52 [2] 85 52 [2] ba 4e }

  condition:
    any of them
}