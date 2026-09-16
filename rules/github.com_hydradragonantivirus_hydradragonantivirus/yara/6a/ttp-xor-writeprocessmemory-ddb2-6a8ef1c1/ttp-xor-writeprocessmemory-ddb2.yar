rule TTP_XOR_WriteProcessMemory_ddb2 {
  strings:
    $key_ddb2 = { 8a c0 [2] b8 e2 [2] be d7 [2] 90 d7 [2] af cb }

  condition:
    any of them
}