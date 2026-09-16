rule TTP_XOR_WriteProcessMemory_9cd8 {
  strings:
    $key_9cd8 = { cb aa [2] f9 88 [2] ff bd [2] d1 bd [2] ee a1 }

  condition:
    any of them
}