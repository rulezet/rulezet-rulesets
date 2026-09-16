rule TTP_XOR_WriteProcessMemory_b76d {
  strings:
    $key_b76d = { e0 1f [2] d2 3d [2] d4 08 [2] fa 08 [2] c5 14 }

  condition:
    any of them
}