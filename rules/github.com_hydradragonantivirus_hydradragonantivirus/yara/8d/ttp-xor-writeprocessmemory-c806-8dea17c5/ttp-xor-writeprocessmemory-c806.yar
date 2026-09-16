rule TTP_XOR_WriteProcessMemory_c806 {
  strings:
    $key_c806 = { 9f 74 [2] ad 56 [2] ab 63 [2] 85 63 [2] ba 7f }

  condition:
    any of them
}