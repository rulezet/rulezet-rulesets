rule TTP_XOR_WriteProcessMemory_d135 {
  strings:
    $key_d135 = { 86 47 [2] b4 65 [2] b2 50 [2] 9c 50 [2] a3 4c }

  condition:
    any of them
}