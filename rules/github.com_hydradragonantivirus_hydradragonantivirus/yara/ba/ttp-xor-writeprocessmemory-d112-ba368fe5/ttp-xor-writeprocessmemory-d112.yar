rule TTP_XOR_WriteProcessMemory_d112 {
  strings:
    $key_d112 = { 86 60 [2] b4 42 [2] b2 77 [2] 9c 77 [2] a3 6b }

  condition:
    any of them
}