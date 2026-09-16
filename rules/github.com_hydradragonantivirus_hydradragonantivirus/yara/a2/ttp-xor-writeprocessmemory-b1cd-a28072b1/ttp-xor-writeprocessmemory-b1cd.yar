rule TTP_XOR_WriteProcessMemory_b1cd {
  strings:
    $key_b1cd = { e6 bf [2] d4 9d [2] d2 a8 [2] fc a8 [2] c3 b4 }

  condition:
    any of them
}