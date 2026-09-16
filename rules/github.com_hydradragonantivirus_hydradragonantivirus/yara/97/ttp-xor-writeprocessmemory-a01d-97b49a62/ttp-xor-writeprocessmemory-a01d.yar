rule TTP_XOR_WriteProcessMemory_a01d {
  strings:
    $key_a01d = { f7 6f [2] c5 4d [2] c3 78 [2] ed 78 [2] d2 64 }

  condition:
    any of them
}