rule TTP_XOR_WriteProcessMemory_9ca8 {
  strings:
    $key_9ca8 = { cb da [2] f9 f8 [2] ff cd [2] d1 cd [2] ee d1 }

  condition:
    any of them
}