rule TTP_XOR_WriteProcessMemory_b2cd {
  strings:
    $key_b2cd = { e5 bf [2] d7 9d [2] d1 a8 [2] ff a8 [2] c0 b4 }

  condition:
    any of them
}