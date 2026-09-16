rule TTP_XOR_WriteProcessMemory_e7ee {
  strings:
    $key_e7ee = { b0 9c [2] 82 be [2] 84 8b [2] aa 8b [2] 95 97 }

  condition:
    any of them
}