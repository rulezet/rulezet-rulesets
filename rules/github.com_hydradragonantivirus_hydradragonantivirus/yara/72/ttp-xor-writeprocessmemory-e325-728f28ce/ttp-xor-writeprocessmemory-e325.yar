rule TTP_XOR_WriteProcessMemory_e325 {
  strings:
    $key_e325 = { b4 57 [2] 86 75 [2] 80 40 [2] ae 40 [2] 91 5c }

  condition:
    any of them
}