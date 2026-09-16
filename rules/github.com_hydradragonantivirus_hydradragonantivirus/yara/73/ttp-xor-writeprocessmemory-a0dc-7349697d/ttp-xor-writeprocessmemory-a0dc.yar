rule TTP_XOR_WriteProcessMemory_a0dc {
  strings:
    $key_a0dc = { f7 ae [2] c5 8c [2] c3 b9 [2] ed b9 [2] d2 a5 }

  condition:
    any of them
}