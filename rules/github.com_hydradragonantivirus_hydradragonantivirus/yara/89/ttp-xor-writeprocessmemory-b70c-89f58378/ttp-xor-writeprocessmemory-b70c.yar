rule TTP_XOR_WriteProcessMemory_b70c {
  strings:
    $key_b70c = { e0 7e [2] d2 5c [2] d4 69 [2] fa 69 [2] c5 75 }

  condition:
    any of them
}