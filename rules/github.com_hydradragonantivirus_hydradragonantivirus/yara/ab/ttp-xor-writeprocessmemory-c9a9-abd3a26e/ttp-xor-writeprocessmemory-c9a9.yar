rule TTP_XOR_WriteProcessMemory_c9a9 {
  strings:
    $key_c9a9 = { 9e db [2] ac f9 [2] aa cc [2] 84 cc [2] bb d0 }

  condition:
    any of them
}