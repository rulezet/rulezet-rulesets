rule TTP_XOR_WriteProcessMemory_9cc0 {
  strings:
    $key_9cc0 = { cb b2 [2] f9 90 [2] ff a5 [2] d1 a5 [2] ee b9 }

  condition:
    any of them
}