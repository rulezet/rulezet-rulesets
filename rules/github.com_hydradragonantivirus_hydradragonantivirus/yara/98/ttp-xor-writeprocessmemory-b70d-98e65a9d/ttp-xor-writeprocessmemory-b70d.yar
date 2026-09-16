rule TTP_XOR_WriteProcessMemory_b70d {
  strings:
    $key_b70d = { e0 7f [2] d2 5d [2] d4 68 [2] fa 68 [2] c5 74 }

  condition:
    any of them
}