rule TTP_XOR_WriteProcessMemory_c00c {
  strings:
    $key_c00c = { 97 7e [2] a5 5c [2] a3 69 [2] 8d 69 [2] b2 75 }

  condition:
    any of them
}