rule TTP_XOR_WriteProcessMemory_9cd0 {
  strings:
    $key_9cd0 = { cb a2 [2] f9 80 [2] ff b5 [2] d1 b5 [2] ee a9 }

  condition:
    any of them
}