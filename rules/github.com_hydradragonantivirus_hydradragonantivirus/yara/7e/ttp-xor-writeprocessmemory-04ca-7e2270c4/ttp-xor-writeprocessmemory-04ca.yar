rule TTP_XOR_WriteProcessMemory_04ca {
  strings:
    $key_04ca = { 53 b8 [2] 61 9a [2] 67 af [2] 49 af [2] 76 b3 }

  condition:
    any of them
}