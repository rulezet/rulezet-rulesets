rule TTP_XOR_WriteProcessMemory_216c {
  strings:
    $key_216c = { 76 1e [2] 44 3c [2] 42 09 [2] 6c 09 [2] 53 15 }

  condition:
    any of them
}