rule TTP_XOR_WriteProcessMemory_45ca {
  strings:
    $key_45ca = { 12 b8 [2] 20 9a [2] 26 af [2] 08 af [2] 37 b3 }

  condition:
    any of them
}