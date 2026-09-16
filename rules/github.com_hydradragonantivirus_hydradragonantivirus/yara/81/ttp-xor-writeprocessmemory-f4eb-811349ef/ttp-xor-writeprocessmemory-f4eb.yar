rule TTP_XOR_WriteProcessMemory_f4eb {
  strings:
    $key_f4eb = { a3 99 [2] 91 bb [2] 97 8e [2] b9 8e [2] 86 92 }

  condition:
    any of them
}