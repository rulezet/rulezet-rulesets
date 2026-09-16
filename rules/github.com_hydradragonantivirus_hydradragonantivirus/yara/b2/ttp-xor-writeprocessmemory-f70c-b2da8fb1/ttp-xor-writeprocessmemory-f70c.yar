rule TTP_XOR_WriteProcessMemory_f70c {
  strings:
    $key_f70c = { a0 7e [2] 92 5c [2] 94 69 [2] ba 69 [2] 85 75 }

  condition:
    any of them
}