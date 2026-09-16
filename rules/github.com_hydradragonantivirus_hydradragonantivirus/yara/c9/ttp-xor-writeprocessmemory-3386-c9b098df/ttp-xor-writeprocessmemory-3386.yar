rule TTP_XOR_WriteProcessMemory_3386 {
  strings:
    $key_3386 = { 64 f4 [2] 56 d6 [2] 50 e3 [2] 7e e3 [2] 41 ff }

  condition:
    any of them
}