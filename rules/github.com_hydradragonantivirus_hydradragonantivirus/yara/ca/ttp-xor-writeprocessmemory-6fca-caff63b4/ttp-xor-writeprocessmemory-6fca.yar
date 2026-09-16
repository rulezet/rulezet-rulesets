rule TTP_XOR_WriteProcessMemory_6fca {
  strings:
    $key_6fca = { 38 b8 [2] 0a 9a [2] 0c af [2] 22 af [2] 1d b3 }

  condition:
    any of them
}