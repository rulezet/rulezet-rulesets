rule TTP_XOR_WriteProcessMemory_b169 {
  strings:
    $key_b169 = { e6 1b [2] d4 39 [2] d2 0c [2] fc 0c [2] c3 10 }

  condition:
    any of them
}