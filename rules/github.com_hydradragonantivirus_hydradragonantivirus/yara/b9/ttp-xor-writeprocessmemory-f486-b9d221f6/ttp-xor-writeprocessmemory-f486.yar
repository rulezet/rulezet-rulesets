rule TTP_XOR_WriteProcessMemory_f486 {
  strings:
    $key_f486 = { a3 f4 [2] 91 d6 [2] 97 e3 [2] b9 e3 [2] 86 ff }

  condition:
    any of them
}