rule TTP_XOR_WriteProcessMemory_b74c {
  strings:
    $key_b74c = { e0 3e [2] d2 1c [2] d4 29 [2] fa 29 [2] c5 35 }

  condition:
    any of them
}