rule TTP_XOR_WriteProcessMemory_7fca {
  strings:
    $key_7fca = { 28 b8 [2] 1a 9a [2] 1c af [2] 32 af [2] 0d b3 }

  condition:
    any of them
}