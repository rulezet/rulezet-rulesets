rule TTP_XOR_WriteProcessMemory_323d {
  strings:
    $key_323d = { 65 4f [2] 57 6d [2] 51 58 [2] 7f 58 [2] 40 44 }

  condition:
    any of them
}