rule TTP_XOR_WriteProcessMemory_3365 {
  strings:
    $key_3365 = { 64 17 [2] 56 35 [2] 50 00 [2] 7e 00 [2] 41 1c }

  condition:
    any of them
}