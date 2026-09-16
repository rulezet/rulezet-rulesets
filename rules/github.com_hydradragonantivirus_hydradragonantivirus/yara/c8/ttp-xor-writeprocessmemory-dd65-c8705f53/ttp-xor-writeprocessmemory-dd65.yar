rule TTP_XOR_WriteProcessMemory_dd65 {
  strings:
    $key_dd65 = { 8a 17 [2] b8 35 [2] be 00 [2] 90 00 [2] af 1c }

  condition:
    any of them
}