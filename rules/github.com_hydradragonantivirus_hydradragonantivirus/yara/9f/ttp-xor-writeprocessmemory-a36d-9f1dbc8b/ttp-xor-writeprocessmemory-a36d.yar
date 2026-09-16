rule TTP_XOR_WriteProcessMemory_a36d {
  strings:
    $key_a36d = { f4 1f [2] c6 3d [2] c0 08 [2] ee 08 [2] d1 14 }

  condition:
    any of them
}