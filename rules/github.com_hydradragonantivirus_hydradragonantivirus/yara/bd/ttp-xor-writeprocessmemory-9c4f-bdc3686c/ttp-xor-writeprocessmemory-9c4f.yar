rule TTP_XOR_WriteProcessMemory_9c4f {
  strings:
    $key_9c4f = { cb 3d [2] f9 1f [2] ff 2a [2] d1 2a [2] ee 36 }

  condition:
    any of them
}