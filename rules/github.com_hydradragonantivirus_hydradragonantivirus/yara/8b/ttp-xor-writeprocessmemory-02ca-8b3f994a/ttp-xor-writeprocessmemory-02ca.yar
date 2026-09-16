rule TTP_XOR_WriteProcessMemory_02ca {
  strings:
    $key_02ca = { 55 b8 [2] 67 9a [2] 61 af [2] 4f af [2] 70 b3 }

  condition:
    any of them
}