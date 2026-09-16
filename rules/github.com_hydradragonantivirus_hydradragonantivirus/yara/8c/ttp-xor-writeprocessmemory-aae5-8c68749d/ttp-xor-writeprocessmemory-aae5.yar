rule TTP_XOR_WriteProcessMemory_aae5 {
  strings:
    $key_aae5 = { fd 97 [2] cf b5 [2] c9 80 [2] e7 80 [2] d8 9c }

  condition:
    any of them
}