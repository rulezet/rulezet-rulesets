rule TTP_XOR_WriteProcessMemory_250d {
  strings:
    $key_250d = { 72 7f [2] 40 5d [2] 46 68 [2] 68 68 [2] 57 74 }

  condition:
    any of them
}