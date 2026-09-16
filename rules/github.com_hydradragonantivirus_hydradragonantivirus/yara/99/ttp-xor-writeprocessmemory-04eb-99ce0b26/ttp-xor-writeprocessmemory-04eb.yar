rule TTP_XOR_WriteProcessMemory_04eb {
  strings:
    $key_04eb = { 53 99 [2] 61 bb [2] 67 8e [2] 49 8e [2] 76 92 }

  condition:
    any of them
}