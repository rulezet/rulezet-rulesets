rule TTP_XOR_WriteProcessMemory_136c {
  strings:
    $key_136c = { 44 1e [2] 76 3c [2] 70 09 [2] 5e 09 [2] 61 15 }

  condition:
    any of them
}