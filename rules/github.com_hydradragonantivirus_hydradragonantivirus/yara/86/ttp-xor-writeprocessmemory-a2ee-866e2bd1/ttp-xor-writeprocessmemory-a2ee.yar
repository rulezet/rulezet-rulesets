rule TTP_XOR_WriteProcessMemory_a2ee {
  strings:
    $key_a2ee = { f5 9c [2] c7 be [2] c1 8b [2] ef 8b [2] d0 97 }

  condition:
    any of them
}