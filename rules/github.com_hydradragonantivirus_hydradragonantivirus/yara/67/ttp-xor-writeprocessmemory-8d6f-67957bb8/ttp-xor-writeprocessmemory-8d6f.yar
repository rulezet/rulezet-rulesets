rule TTP_XOR_WriteProcessMemory_8d6f {
  strings:
    $key_8d6f = { da 1d [2] e8 3f [2] ee 0a [2] c0 0a [2] ff 16 }

  condition:
    any of them
}