rule TTP_XOR_WriteProcessMemory_9c93 {
  strings:
    $key_9c93 = { cb e1 [2] f9 c3 [2] ff f6 [2] d1 f6 [2] ee ea }

  condition:
    any of them
}