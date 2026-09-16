rule TTP_XOR_WriteProcessMemory_dd17 {
  strings:
    $key_dd17 = { 8a 65 [2] b8 47 [2] be 72 [2] 90 72 [2] af 6e }

  condition:
    any of them
}