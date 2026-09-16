rule TTP_XOR_WriteProcessMemory_43c8 {
  strings:
    $key_43c8 = { 14 ba [2] 26 98 [2] 20 ad [2] 0e ad [2] 31 b1 }

  condition:
    any of them
}