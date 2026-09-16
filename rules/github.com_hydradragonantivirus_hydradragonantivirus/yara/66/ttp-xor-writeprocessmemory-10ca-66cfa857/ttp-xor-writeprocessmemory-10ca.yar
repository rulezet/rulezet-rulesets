rule TTP_XOR_WriteProcessMemory_10ca {
  strings:
    $key_10ca = { 47 b8 [2] 75 9a [2] 73 af [2] 5d af [2] 62 b3 }

  condition:
    any of them
}