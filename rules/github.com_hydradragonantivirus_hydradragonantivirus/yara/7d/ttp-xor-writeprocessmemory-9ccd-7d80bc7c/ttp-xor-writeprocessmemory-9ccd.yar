rule TTP_XOR_WriteProcessMemory_9ccd {
  strings:
    $key_9ccd = { cb bf [2] f9 9d [2] ff a8 [2] d1 a8 [2] ee b4 }

  condition:
    any of them
}