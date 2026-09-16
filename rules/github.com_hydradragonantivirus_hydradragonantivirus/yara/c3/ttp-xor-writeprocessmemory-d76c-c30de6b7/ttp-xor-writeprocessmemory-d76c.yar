rule TTP_XOR_WriteProcessMemory_d76c {
  strings:
    $key_d76c = { 80 1e [2] b2 3c [2] b4 09 [2] 9a 09 [2] a5 15 }

  condition:
    any of them
}