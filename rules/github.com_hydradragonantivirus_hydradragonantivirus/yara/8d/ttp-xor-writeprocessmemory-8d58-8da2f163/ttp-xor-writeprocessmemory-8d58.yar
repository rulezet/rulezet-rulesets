rule TTP_XOR_WriteProcessMemory_8d58 {
  strings:
    $key_8d58 = { da 2a [2] e8 08 [2] ee 3d [2] c0 3d [2] ff 21 }

  condition:
    any of them
}