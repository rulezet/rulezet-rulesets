rule TTP_XOR_WriteProcessMemory_dd13 {
  strings:
    $key_dd13 = { 8a 61 [2] b8 43 [2] be 76 [2] 90 76 [2] af 6a }

  condition:
    any of them
}