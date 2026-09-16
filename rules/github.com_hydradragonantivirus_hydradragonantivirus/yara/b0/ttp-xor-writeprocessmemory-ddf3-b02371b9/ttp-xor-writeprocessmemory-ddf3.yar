rule TTP_XOR_WriteProcessMemory_ddf3 {
  strings:
    $key_ddf3 = { 8a 81 [2] b8 a3 [2] be 96 [2] 90 96 [2] af 8a }

  condition:
    any of them
}