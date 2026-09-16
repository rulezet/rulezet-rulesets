rule TTP_XOR_WriteProcessMemory_dde5 {
  strings:
    $key_dde5 = { 8a 97 [2] b8 b5 [2] be 80 [2] 90 80 [2] af 9c }

  condition:
    any of them
}