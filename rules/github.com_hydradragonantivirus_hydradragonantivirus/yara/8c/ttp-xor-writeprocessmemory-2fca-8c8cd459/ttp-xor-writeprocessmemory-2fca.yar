rule TTP_XOR_WriteProcessMemory_2fca {
  strings:
    $key_2fca = { 78 b8 [2] 4a 9a [2] 4c af [2] 62 af [2] 5d b3 }

  condition:
    any of them
}