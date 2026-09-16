rule TTP_XOR_WriteProcessMemory_dd75 {
  strings:
    $key_dd75 = { 8a 07 [2] b8 25 [2] be 10 [2] 90 10 [2] af 0c }

  condition:
    any of them
}