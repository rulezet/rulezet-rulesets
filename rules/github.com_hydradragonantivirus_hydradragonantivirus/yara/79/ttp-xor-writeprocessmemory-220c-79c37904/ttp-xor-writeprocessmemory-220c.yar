rule TTP_XOR_WriteProcessMemory_220c {
  strings:
    $key_220c = { 75 7e [2] 47 5c [2] 41 69 [2] 6f 69 [2] 50 75 }

  condition:
    any of them
}