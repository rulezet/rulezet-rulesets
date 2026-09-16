rule TTP_XOR_WriteProcessMemory_450d {
  strings:
    $key_450d = { 12 7f [2] 20 5d [2] 26 68 [2] 08 68 [2] 37 74 }

  condition:
    any of them
}