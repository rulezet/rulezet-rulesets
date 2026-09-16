rule TTP_XOR_WriteProcessMemory_175d {
  strings:
    $key_175d = { 40 2f [2] 72 0d [2] 74 38 [2] 5a 38 [2] 65 24 }

  condition:
    any of them
}