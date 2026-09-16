rule TTP_XOR_WriteProcessMemory_341d {
  strings:
    $key_341d = { 63 6f [2] 51 4d [2] 57 78 [2] 79 78 [2] 46 64 }

  condition:
    any of them
}