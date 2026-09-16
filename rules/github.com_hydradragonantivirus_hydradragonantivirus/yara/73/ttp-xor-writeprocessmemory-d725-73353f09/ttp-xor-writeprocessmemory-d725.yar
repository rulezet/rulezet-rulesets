rule TTP_XOR_WriteProcessMemory_d725 {
  strings:
    $key_d725 = { 80 57 [2] b2 75 [2] b4 40 [2] 9a 40 [2] a5 5c }

  condition:
    any of them
}