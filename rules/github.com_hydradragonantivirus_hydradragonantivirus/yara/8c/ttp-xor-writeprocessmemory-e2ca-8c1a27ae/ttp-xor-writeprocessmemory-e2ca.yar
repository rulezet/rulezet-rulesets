rule TTP_XOR_WriteProcessMemory_e2ca {
  strings:
    $key_e2ca = { b5 b8 [2] 87 9a [2] 81 af [2] af af [2] 90 b3 }

  condition:
    any of them
}