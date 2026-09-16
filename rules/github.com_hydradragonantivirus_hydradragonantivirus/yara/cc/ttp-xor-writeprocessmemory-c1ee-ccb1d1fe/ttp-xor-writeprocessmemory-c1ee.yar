rule TTP_XOR_WriteProcessMemory_c1ee {
  strings:
    $key_c1ee = { 96 9c [2] a4 be [2] a2 8b [2] 8c 8b [2] b3 97 }

  condition:
    any of them
}