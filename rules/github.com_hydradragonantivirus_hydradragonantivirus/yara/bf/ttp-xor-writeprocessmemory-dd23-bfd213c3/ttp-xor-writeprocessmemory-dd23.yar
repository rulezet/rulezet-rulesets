rule TTP_XOR_WriteProcessMemory_dd23 {
  strings:
    $key_dd23 = { 8a 51 [2] b8 73 [2] be 46 [2] 90 46 [2] af 5a }

  condition:
    any of them
}