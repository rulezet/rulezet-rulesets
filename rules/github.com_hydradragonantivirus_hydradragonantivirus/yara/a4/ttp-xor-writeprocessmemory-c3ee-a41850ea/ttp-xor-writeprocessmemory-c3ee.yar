rule TTP_XOR_WriteProcessMemory_c3ee {
  strings:
    $key_c3ee = { 94 9c [2] a6 be [2] a0 8b [2] 8e 8b [2] b1 97 }

  condition:
    any of them
}