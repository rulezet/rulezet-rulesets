rule TTP_XOR_WriteProcessMemory_f413 {
  strings:
    $key_f413 = { a3 61 [2] 91 43 [2] 97 76 [2] b9 76 [2] 86 6a }

  condition:
    any of them
}