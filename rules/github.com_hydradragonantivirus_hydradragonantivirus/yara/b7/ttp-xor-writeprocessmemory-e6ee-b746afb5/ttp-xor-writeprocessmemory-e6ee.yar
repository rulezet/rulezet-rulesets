rule TTP_XOR_WriteProcessMemory_e6ee {
  strings:
    $key_e6ee = { b1 9c [2] 83 be [2] 85 8b [2] ab 8b [2] 94 97 }

  condition:
    any of them
}