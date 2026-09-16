rule TTP_XOR_WriteProcessMemory_d6ee {
  strings:
    $key_d6ee = { 81 9c [2] b3 be [2] b5 8b [2] 9b 8b [2] a4 97 }

  condition:
    any of them
}