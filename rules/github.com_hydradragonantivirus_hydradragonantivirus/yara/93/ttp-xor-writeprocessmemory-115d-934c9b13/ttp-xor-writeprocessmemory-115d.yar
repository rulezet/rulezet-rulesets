rule TTP_XOR_WriteProcessMemory_115d {
  strings:
    $key_115d = { 46 2f [2] 74 0d [2] 72 38 [2] 5c 38 [2] 63 24 }

  condition:
    any of them
}