rule TTP_XOR_WriteProcessMemory_25ca {
  strings:
    $key_25ca = { 72 b8 [2] 40 9a [2] 46 af [2] 68 af [2] 57 b3 }

  condition:
    any of them
}