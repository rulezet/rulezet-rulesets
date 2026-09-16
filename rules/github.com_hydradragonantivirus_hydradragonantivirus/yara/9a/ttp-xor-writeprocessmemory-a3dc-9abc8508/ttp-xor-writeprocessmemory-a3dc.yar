rule TTP_XOR_WriteProcessMemory_a3dc {
  strings:
    $key_a3dc = { f4 ae [2] c6 8c [2] c0 b9 [2] ee b9 [2] d1 a5 }

  condition:
    any of them
}