rule TTP_XOR_WriteProcessMemory_9c97 {
  strings:
    $key_9c97 = { cb e5 [2] f9 c7 [2] ff f2 [2] d1 f2 [2] ee ee }

  condition:
    any of them
}