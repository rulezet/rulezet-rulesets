rule TTP_XOR_WriteProcessMemory_354d {
  strings:
    $key_354d = { 62 3f [2] 50 1d [2] 56 28 [2] 78 28 [2] 47 34 }

  condition:
    any of them
}