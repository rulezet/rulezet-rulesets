rule TTP_XOR_WriteProcessMemory_23ee {
  strings:
    $key_23ee = { 74 9c [2] 46 be [2] 40 8b [2] 6e 8b [2] 51 97 }

  condition:
    any of them
}