rule TTP_XOR_WriteProcessMemory_0d80 {
  strings:
    $key_0d80 = { 5a f2 [2] 68 d0 [2] 6e e5 [2] 40 e5 [2] 7f f9 }

  condition:
    any of them
}