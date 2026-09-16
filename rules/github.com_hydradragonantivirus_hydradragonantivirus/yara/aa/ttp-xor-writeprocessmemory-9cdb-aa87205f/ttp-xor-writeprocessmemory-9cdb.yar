rule TTP_XOR_WriteProcessMemory_9cdb {
  strings:
    $key_9cdb = { cb a9 [2] f9 8b [2] ff be [2] d1 be [2] ee a2 }

  condition:
    any of them
}