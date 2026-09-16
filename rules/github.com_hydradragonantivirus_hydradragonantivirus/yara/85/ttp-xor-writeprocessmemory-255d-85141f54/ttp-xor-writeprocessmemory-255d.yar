rule TTP_XOR_WriteProcessMemory_255d {
  strings:
    $key_255d = { 72 2f [2] 40 0d [2] 46 38 [2] 68 38 [2] 57 24 }

  condition:
    any of them
}