rule TTP_XOR_WriteProcessMemory_dd22 {
  strings:
    $key_dd22 = { 8a 50 [2] b8 72 [2] be 47 [2] 90 47 [2] af 5b }

  condition:
    any of them
}