rule TTP_XOR_WriteProcessMemory_9cc5 {
  strings:
    $key_9cc5 = { cb b7 [2] f9 95 [2] ff a0 [2] d1 a0 [2] ee bc }

  condition:
    any of them
}