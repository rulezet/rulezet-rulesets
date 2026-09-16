rule TTP_XOR_WriteProcessMemory_425d {
  strings:
    $key_425d = { 15 2f [2] 27 0d [2] 21 38 [2] 0f 38 [2] 30 24 }

  condition:
    any of them
}