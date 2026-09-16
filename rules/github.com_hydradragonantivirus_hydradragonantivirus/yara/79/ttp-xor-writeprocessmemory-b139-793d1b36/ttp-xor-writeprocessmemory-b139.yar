rule TTP_XOR_WriteProcessMemory_b139 {
  strings:
    $key_b139 = { e6 4b [2] d4 69 [2] d2 5c [2] fc 5c [2] c3 40 }

  condition:
    any of them
}