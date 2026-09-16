rule TTP_XOR_WriteProcessMemory_b0cd {
  strings:
    $key_b0cd = { e7 bf [2] d5 9d [2] d3 a8 [2] fd a8 [2] c2 b4 }

  condition:
    any of them
}