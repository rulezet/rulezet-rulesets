rule TTP_XOR_WriteProcessMemory_ddf0 {
  strings:
    $key_ddf0 = { 8a 82 [2] b8 a0 [2] be 95 [2] 90 95 [2] af 89 }

  condition:
    any of them
}