rule TTP_XOR_WriteProcessMemory_57ca {
  strings:
    $key_57ca = { 00 b8 [2] 32 9a [2] 34 af [2] 1a af [2] 25 b3 }

  condition:
    any of them
}