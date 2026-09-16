rule TTP_XOR_WriteProcessMemory_541d {
  strings:
    $key_541d = { 03 6f [2] 31 4d [2] 37 78 [2] 19 78 [2] 26 64 }

  condition:
    any of them
}