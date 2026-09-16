rule TTP_XOR_WriteProcessMemory_251d {
  strings:
    $key_251d = { 72 6f [2] 40 4d [2] 46 78 [2] 68 78 [2] 57 64 }

  condition:
    any of them
}