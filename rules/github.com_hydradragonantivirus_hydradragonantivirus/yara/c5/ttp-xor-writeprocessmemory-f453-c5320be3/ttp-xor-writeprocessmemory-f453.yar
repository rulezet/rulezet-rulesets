rule TTP_XOR_WriteProcessMemory_f453 {
  strings:
    $key_f453 = { a3 21 [2] 91 03 [2] 97 36 [2] b9 36 [2] 86 2a }

  condition:
    any of them
}