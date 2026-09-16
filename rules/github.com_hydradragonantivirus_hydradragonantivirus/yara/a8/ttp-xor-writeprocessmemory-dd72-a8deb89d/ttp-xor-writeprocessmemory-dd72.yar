rule TTP_XOR_WriteProcessMemory_dd72 {
  strings:
    $key_dd72 = { 8a 00 [2] b8 22 [2] be 17 [2] 90 17 [2] af 0b }

  condition:
    any of them
}