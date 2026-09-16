rule TTP_XOR_WriteProcessMemory_5dca {
  strings:
    $key_5dca = { 0a b8 [2] 38 9a [2] 3e af [2] 10 af [2] 2f b3 }

  condition:
    any of them
}