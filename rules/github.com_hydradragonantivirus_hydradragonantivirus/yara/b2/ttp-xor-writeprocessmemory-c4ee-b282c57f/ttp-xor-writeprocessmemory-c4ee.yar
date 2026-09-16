rule TTP_XOR_WriteProcessMemory_c4ee {
  strings:
    $key_c4ee = { 93 9c [2] a1 be [2] a7 8b [2] 89 8b [2] b6 97 }

  condition:
    any of them
}