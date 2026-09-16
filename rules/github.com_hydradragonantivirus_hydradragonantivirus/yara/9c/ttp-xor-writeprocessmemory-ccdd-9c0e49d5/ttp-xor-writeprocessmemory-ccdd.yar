rule TTP_XOR_WriteProcessMemory_ccdd {
  strings:
    $key_ccdd = { 9b af [2] a9 8d [2] af b8 [2] 81 b8 [2] be a4 }

  condition:
    any of them
}