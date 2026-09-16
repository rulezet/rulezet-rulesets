rule TTP_XOR_WriteProcessMemory_dd25 {
  strings:
    $key_dd25 = { 8a 57 [2] b8 75 [2] be 40 [2] 90 40 [2] af 5c }

  condition:
    any of them
}