rule TTP_XOR_WriteProcessMemory_ff97 {
  strings:
    $key_ff97 = { a8 e5 [2] 9a c7 [2] 9c f2 [2] b2 f2 [2] 8d ee }

  condition:
    any of them
}