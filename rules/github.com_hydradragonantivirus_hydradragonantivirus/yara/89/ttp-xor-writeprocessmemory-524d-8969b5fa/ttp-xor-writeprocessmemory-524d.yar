rule TTP_XOR_WriteProcessMemory_524d {
  strings:
    $key_524d = { 05 3f [2] 37 1d [2] 31 28 [2] 1f 28 [2] 20 34 }

  condition:
    any of them
}