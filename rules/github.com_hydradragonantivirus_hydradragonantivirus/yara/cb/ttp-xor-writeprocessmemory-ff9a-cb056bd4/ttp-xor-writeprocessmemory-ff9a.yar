rule TTP_XOR_WriteProcessMemory_ff9a {
  strings:
    $key_ff9a = { a8 e8 [2] 9a ca [2] 9c ff [2] b2 ff [2] 8d e3 }

  condition:
    any of them
}