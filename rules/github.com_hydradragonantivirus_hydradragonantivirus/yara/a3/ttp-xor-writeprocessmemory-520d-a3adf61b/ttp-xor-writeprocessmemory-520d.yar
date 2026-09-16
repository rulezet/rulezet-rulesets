rule TTP_XOR_WriteProcessMemory_520d {
  strings:
    $key_520d = { 05 7f [2] 37 5d [2] 31 68 [2] 1f 68 [2] 20 74 }

  condition:
    any of them
}