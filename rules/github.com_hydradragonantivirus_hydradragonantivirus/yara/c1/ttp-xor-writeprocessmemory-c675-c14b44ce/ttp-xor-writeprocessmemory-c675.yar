rule TTP_XOR_WriteProcessMemory_c675 {
  strings:
    $key_c675 = { 91 07 [2] a3 25 [2] a5 10 [2] 8b 10 [2] b4 0c }

  condition:
    any of them
}