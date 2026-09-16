rule TTP_XOR_WriteProcessMemory_9cde {
  strings:
    $key_9cde = { cb ac [2] f9 8e [2] ff bb [2] d1 bb [2] ee a7 }

  condition:
    any of them
}