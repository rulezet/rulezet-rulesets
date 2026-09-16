rule TTP_XOR_WriteProcessMemory_75ca {
  strings:
    $key_75ca = { 22 b8 [2] 10 9a [2] 16 af [2] 38 af [2] 07 b3 }

  condition:
    any of them
}