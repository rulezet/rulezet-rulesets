rule TTP_XOR_WriteProcessMemory_9cce {
  strings:
    $key_9cce = { cb bc [2] f9 9e [2] ff ab [2] d1 ab [2] ee b7 }

  condition:
    any of them
}