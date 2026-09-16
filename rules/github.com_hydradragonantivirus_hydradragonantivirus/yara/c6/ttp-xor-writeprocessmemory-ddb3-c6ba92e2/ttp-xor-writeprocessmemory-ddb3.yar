rule TTP_XOR_WriteProcessMemory_ddb3 {
  strings:
    $key_ddb3 = { 8a c1 [2] b8 e3 [2] be d6 [2] 90 d6 [2] af ca }

  condition:
    any of them
}