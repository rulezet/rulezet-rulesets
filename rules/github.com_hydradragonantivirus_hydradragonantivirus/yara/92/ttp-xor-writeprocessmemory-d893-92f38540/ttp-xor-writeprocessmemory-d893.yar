rule TTP_XOR_WriteProcessMemory_d893 {
  strings:
    $key_d893 = { 8f e1 [2] bd c3 [2] bb f6 [2] 95 f6 [2] aa ea }

  condition:
    any of them
}