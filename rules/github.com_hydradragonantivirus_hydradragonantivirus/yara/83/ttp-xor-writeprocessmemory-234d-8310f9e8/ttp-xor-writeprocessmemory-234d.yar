rule TTP_XOR_WriteProcessMemory_234d {
  strings:
    $key_234d = { 74 3f [2] 46 1d [2] 40 28 [2] 6e 28 [2] 51 34 }

  condition:
    any of them
}