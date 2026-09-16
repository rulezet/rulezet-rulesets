rule TTP_XOR_WriteProcessMemory_224e {
  strings:
    $key_224e = { 75 3c [2] 47 1e [2] 41 2b [2] 6f 2b [2] 50 37 }

  condition:
    any of them
}