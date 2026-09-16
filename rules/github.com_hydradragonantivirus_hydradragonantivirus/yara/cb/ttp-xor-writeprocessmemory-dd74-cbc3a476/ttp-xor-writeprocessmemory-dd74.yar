rule TTP_XOR_WriteProcessMemory_dd74 {
  strings:
    $key_dd74 = { 8a 06 [2] b8 24 [2] be 11 [2] 90 11 [2] af 0d }

  condition:
    any of them
}