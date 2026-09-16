rule TTP_XOR_WriteProcessMemory_9cca {
  strings:
    $key_9cca = { cb b8 [2] f9 9a [2] ff af [2] d1 af [2] ee b3 }

  condition:
    any of them
}