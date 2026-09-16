rule TTP_XOR_WriteProcessMemory_ddb0 {
  strings:
    $key_ddb0 = { 8a c2 [2] b8 e0 [2] be d5 [2] 90 d5 [2] af c9 }

  condition:
    any of them
}