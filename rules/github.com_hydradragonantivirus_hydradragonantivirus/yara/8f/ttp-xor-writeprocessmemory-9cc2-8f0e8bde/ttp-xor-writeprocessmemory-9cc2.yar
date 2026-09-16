rule TTP_XOR_WriteProcessMemory_9cc2 {
  strings:
    $key_9cc2 = { cb b0 [2] f9 92 [2] ff a7 [2] d1 a7 [2] ee bb }

  condition:
    any of them
}