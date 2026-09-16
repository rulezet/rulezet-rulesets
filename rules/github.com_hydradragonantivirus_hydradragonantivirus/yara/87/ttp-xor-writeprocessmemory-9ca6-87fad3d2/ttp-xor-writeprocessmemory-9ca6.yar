rule TTP_XOR_WriteProcessMemory_9ca6 {
  strings:
    $key_9ca6 = { cb d4 [2] f9 f6 [2] ff c3 [2] d1 c3 [2] ee df }

  condition:
    any of them
}