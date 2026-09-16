rule TTP_XOR_WriteProcessMemory_b727 {
  strings:
    $key_b727 = { e0 55 [2] d2 77 [2] d4 42 [2] fa 42 [2] c5 5e }

  condition:
    any of them
}