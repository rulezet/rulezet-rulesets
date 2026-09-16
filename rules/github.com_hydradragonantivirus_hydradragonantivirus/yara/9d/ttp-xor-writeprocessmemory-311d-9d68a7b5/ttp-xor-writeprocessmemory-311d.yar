rule TTP_XOR_WriteProcessMemory_311d {
  strings:
    $key_311d = { 66 6f [2] 54 4d [2] 52 78 [2] 7c 78 [2] 43 64 }

  condition:
    any of them
}