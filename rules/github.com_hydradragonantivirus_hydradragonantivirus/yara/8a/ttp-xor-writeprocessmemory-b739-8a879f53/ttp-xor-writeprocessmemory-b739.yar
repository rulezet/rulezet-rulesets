rule TTP_XOR_WriteProcessMemory_b739 {
  strings:
    $key_b739 = { e0 4b [2] d2 69 [2] d4 5c [2] fa 5c [2] c5 40 }

  condition:
    any of them
}