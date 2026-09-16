rule TTP_XOR_WriteProcessMemory_a37a {
  strings:
    $key_a37a = { f4 08 [2] c6 2a [2] c0 1f [2] ee 1f [2] d1 03 }

  condition:
    any of them
}