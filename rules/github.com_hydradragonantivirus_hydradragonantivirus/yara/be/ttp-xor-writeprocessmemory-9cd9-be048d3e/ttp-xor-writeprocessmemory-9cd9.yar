rule TTP_XOR_WriteProcessMemory_9cd9 {
  strings:
    $key_9cd9 = { cb ab [2] f9 89 [2] ff bc [2] d1 bc [2] ee a0 }

  condition:
    any of them
}