rule TTP_XOR_WriteProcessMemory_9cc4 {
  strings:
    $key_9cc4 = { cb b6 [2] f9 94 [2] ff a1 [2] d1 a1 [2] ee bd }

  condition:
    any of them
}