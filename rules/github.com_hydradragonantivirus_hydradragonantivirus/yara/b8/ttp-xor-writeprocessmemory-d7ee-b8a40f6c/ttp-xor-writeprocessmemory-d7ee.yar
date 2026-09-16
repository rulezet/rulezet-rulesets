rule TTP_XOR_WriteProcessMemory_d7ee {
  strings:
    $key_d7ee = { 80 9c [2] b2 be [2] b4 8b [2] 9a 8b [2] a5 97 }

  condition:
    any of them
}