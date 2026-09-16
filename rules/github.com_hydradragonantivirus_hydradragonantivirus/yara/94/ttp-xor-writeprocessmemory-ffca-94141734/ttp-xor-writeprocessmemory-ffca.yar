rule TTP_XOR_WriteProcessMemory_ffca {
  strings:
    $key_ffca = { a8 b8 [2] 9a 9a [2] 9c af [2] b2 af [2] 8d b3 }

  condition:
    any of them
}