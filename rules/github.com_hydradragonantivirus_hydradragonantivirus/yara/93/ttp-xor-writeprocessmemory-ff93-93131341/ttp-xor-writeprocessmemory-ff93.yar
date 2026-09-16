rule TTP_XOR_WriteProcessMemory_ff93 {
  strings:
    $key_ff93 = { a8 e1 [2] 9a c3 [2] 9c f6 [2] b2 f6 [2] 8d ea }

  condition:
    any of them
}