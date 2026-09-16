rule TTP_XOR_WriteProcessMemory_1fca {
  strings:
    $key_1fca = { 48 b8 [2] 7a 9a [2] 7c af [2] 52 af [2] 6d b3 }

  condition:
    any of them
}