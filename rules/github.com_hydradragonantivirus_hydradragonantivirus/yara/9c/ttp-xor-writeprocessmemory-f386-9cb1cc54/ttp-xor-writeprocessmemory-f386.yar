rule TTP_XOR_WriteProcessMemory_f386 {
  strings:
    $key_f386 = { a4 f4 [2] 96 d6 [2] 90 e3 [2] be e3 [2] 81 ff }

  condition:
    any of them
}