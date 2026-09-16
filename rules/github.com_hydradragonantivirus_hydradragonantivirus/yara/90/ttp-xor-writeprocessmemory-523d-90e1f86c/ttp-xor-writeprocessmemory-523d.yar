rule TTP_XOR_WriteProcessMemory_523d {
  strings:
    $key_523d = { 05 4f [2] 37 6d [2] 31 58 [2] 1f 58 [2] 20 44 }

  condition:
    any of them
}