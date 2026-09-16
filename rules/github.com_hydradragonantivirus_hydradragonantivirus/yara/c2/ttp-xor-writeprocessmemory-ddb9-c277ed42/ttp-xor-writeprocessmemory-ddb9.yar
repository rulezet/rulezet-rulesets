rule TTP_XOR_WriteProcessMemory_ddb9 {
  strings:
    $key_ddb9 = { 8a cb [2] b8 e9 [2] be dc [2] 90 dc [2] af c0 }

  condition:
    any of them
}