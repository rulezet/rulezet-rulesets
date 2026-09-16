rule TTP_XOR_WriteProcessMemory_77ca {
  strings:
    $key_77ca = { 20 b8 [2] 12 9a [2] 14 af [2] 3a af [2] 05 b3 }

  condition:
    any of them
}