rule TTP_XOR_WriteProcessMemory_8d2f {
  strings:
    $key_8d2f = { da 5d [2] e8 7f [2] ee 4a [2] c0 4a [2] ff 56 }

  condition:
    any of them
}