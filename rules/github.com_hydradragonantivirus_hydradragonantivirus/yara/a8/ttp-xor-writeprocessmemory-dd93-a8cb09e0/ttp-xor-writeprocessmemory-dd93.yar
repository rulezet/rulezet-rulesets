rule TTP_XOR_WriteProcessMemory_dd93 {
  strings:
    $key_dd93 = { 8a e1 [2] b8 c3 [2] be f6 [2] 90 f6 [2] af ea }

  condition:
    any of them
}