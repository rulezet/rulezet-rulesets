rule TTP_XOR_WriteProcessMemory_421d {
  strings:
    $key_421d = { 15 6f [2] 27 4d [2] 21 78 [2] 0f 78 [2] 30 64 }

  condition:
    any of them
}