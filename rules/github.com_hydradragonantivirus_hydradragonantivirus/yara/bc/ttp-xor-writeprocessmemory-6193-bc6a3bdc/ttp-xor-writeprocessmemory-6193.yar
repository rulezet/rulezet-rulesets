rule TTP_XOR_WriteProcessMemory_6193 {
  strings:
    $key_6193 = { 36 e1 [2] 04 c3 [2] 02 f6 [2] 2c f6 [2] 13 ea }

  condition:
    any of them
}