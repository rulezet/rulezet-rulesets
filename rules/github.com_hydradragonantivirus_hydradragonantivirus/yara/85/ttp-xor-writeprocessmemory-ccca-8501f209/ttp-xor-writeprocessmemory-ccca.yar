rule TTP_XOR_WriteProcessMemory_ccca {
  strings:
    $key_ccca = { 9b b8 [2] a9 9a [2] af af [2] 81 af [2] be b3 }

  condition:
    any of them
}