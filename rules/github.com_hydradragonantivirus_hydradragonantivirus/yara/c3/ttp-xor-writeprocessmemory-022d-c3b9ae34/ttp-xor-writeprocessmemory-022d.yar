rule TTP_XOR_WriteProcessMemory_022d {
  strings:
    $key_022d = { 55 5f [2] 67 7d [2] 61 48 [2] 4f 48 [2] 70 54 }

  condition:
    any of them
}