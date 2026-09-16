rule TTP_XOR_WriteProcessMemory_dd45 {
  strings:
    $key_dd45 = { 8a 37 [2] b8 15 [2] be 20 [2] 90 20 [2] af 3c }

  condition:
    any of them
}