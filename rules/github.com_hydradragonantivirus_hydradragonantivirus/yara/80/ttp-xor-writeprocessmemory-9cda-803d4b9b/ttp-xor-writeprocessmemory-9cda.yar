rule TTP_XOR_WriteProcessMemory_9cda {
  strings:
    $key_9cda = { cb a8 [2] f9 8a [2] ff bf [2] d1 bf [2] ee a3 }

  condition:
    any of them
}