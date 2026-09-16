rule TTP_XOR_WriteProcessMemory_efca {
  strings:
    $key_efca = { b8 b8 [2] 8a 9a [2] 8c af [2] a2 af [2] 9d b3 }

  condition:
    any of them
}