rule TTP_XOR_WriteProcessMemory_67ca {
  strings:
    $key_67ca = { 30 b8 [2] 02 9a [2] 04 af [2] 2a af [2] 15 b3 }

  condition:
    any of them
}