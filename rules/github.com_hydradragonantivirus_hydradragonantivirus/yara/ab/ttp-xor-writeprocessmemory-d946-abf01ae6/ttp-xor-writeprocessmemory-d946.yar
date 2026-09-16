rule TTP_XOR_WriteProcessMemory_d946 {
  strings:
    $key_d946 = { 8e 34 [2] bc 16 [2] ba 23 [2] 94 23 [2] ab 3f }

  condition:
    any of them
}