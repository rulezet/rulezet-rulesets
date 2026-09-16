rule TTP_XOR_WriteProcessMemory_9caf {
  strings:
    $key_9caf = { cb dd [2] f9 ff [2] ff ca [2] d1 ca [2] ee d6 }

  condition:
    any of them
}