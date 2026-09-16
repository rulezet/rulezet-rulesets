rule TTP_XOR_WriteProcessMemory_d2ee {
  strings:
    $key_d2ee = { 85 9c [2] b7 be [2] b1 8b [2] 9f 8b [2] a0 97 }

  condition:
    any of them
}