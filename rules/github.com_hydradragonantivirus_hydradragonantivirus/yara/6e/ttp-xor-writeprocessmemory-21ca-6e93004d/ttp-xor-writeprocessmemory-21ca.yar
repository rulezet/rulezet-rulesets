rule TTP_XOR_WriteProcessMemory_21ca {
  strings:
    $key_21ca = { 76 b8 [2] 44 9a [2] 42 af [2] 6c af [2] 53 b3 }

  condition:
    any of them
}