rule TTP_XOR_WriteProcessMemory_b57d {
  strings:
    $key_b57d = { e2 0f [2] d0 2d [2] d6 18 [2] f8 18 [2] c7 04 }

  condition:
    any of them
}