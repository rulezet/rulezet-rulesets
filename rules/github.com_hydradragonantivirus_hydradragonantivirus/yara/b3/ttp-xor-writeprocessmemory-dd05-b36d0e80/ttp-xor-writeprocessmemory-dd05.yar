rule TTP_XOR_WriteProcessMemory_dd05 {
  strings:
    $key_dd05 = { 8a 77 [2] b8 55 [2] be 60 [2] 90 60 [2] af 7c }

  condition:
    any of them
}