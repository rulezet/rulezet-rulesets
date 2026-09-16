rule TTP_XOR_WriteProcessMemory_4b1d {
  strings:
    $key_4b1d = { 1c 6f [2] 2e 4d [2] 28 78 [2] 06 78 [2] 39 64 }

  condition:
    any of them
}