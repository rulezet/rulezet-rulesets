rule TTP_XOR_WriteProcessMemory_741d {
  strings:
    $key_741d = { 23 6f [2] 11 4d [2] 17 78 [2] 39 78 [2] 06 64 }

  condition:
    any of them
}