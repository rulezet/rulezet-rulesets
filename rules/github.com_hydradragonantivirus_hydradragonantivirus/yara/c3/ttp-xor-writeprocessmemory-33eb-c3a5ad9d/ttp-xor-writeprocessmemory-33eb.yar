rule TTP_XOR_WriteProcessMemory_33eb {
  strings:
    $key_33eb = { 64 99 [2] 56 bb [2] 50 8e [2] 7e 8e [2] 41 92 }

  condition:
    any of them
}