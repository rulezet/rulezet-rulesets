rule TTP_XOR_WriteProcessMemory_8d1f {
  strings:
    $key_8d1f = { da 6d [2] e8 4f [2] ee 7a [2] c0 7a [2] ff 66 }

  condition:
    any of them
}