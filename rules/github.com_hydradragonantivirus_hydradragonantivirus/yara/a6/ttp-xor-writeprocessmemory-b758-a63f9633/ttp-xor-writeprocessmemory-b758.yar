rule TTP_XOR_WriteProcessMemory_b758 {
  strings:
    $key_b758 = { e0 2a [2] d2 08 [2] d4 3d [2] fa 3d [2] c5 21 }

  condition:
    any of them
}