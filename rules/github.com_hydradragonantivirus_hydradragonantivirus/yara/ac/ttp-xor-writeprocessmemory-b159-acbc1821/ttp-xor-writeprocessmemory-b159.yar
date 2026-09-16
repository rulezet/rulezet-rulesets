rule TTP_XOR_WriteProcessMemory_b159 {
  strings:
    $key_b159 = { e6 2b [2] d4 09 [2] d2 3c [2] fc 3c [2] c3 20 }

  condition:
    any of them
}