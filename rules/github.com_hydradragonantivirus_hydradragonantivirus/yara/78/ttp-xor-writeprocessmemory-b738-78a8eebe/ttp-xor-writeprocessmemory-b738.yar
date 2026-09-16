rule TTP_XOR_WriteProcessMemory_b738 {
  strings:
    $key_b738 = { e0 4a [2] d2 68 [2] d4 5d [2] fa 5d [2] c5 41 }

  condition:
    any of them
}