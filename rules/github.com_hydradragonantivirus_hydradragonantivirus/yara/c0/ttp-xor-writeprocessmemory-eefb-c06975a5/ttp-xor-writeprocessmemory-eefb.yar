rule TTP_XOR_WriteProcessMemory_eefb {
  strings:
    $key_eefb = { b9 89 [2] 8b ab [2] 8d 9e [2] a3 9e [2] 9c 82 }

  condition:
    any of them
}