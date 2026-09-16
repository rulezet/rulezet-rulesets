rule TTP_XOR_WriteProcessMemory_c8c8 {
  strings:
    $key_c8c8 = { 9f ba [2] ad 98 [2] ab ad [2] 85 ad [2] ba b1 }

  condition:
    any of them
}