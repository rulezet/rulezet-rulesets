rule TTP_XOR_WriteProcessMemory_b7cd {
  strings:
    $key_b7cd = { e0 bf [2] d2 9d [2] d4 a8 [2] fa a8 [2] c5 b4 }

  condition:
    any of them
}