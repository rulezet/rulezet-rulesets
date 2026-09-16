rule TTP_XOR_WriteProcessMemory_31ca {
  strings:
    $key_31ca = { 66 b8 [2] 54 9a [2] 52 af [2] 7c af [2] 43 b3 }

  condition:
    any of them
}