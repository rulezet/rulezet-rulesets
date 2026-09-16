rule TTP_XOR_WriteProcessMemory_e70c {
  strings:
    $key_e70c = { b0 7e [2] 82 5c [2] 84 69 [2] aa 69 [2] 95 75 }

  condition:
    any of them
}