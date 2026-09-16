rule TTP_XOR_WriteProcessMemory_fce5 {
  strings:
    $key_fce5 = { ab 97 [2] 99 b5 [2] 9f 80 [2] b1 80 [2] 8e 9c }

  condition:
    any of them
}