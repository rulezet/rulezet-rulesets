rule TTP_XOR_WriteProcessMemory_9430 {
  strings:
    $key_9430 = { c3 42 [2] f1 60 [2] f7 55 [2] d9 55 [2] e6 49 }

  condition:
    any of them
}