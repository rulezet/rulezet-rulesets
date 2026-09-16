rule TTP_XOR_WriteProcessMemory_c874 {
  strings:
    $key_c874 = { 9f 06 [2] ad 24 [2] ab 11 [2] 85 11 [2] ba 0d }

  condition:
    any of them
}