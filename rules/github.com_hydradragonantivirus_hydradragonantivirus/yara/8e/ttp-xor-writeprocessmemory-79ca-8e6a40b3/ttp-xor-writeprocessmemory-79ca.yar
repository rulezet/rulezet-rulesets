rule TTP_XOR_WriteProcessMemory_79ca {
  strings:
    $key_79ca = { 2e b8 [2] 1c 9a [2] 1a af [2] 34 af [2] 0b b3 }

  condition:
    any of them
}