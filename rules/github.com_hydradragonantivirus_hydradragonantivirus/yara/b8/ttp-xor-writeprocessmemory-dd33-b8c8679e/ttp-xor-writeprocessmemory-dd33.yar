rule TTP_XOR_WriteProcessMemory_dd33 {
  strings:
    $key_dd33 = { 8a 41 [2] b8 63 [2] be 56 [2] 90 56 [2] af 4a }

  condition:
    any of them
}