rule TTP_XOR_WriteProcessMemory_a61d {
  strings:
    $key_a61d = { f1 6f [2] c3 4d [2] c5 78 [2] eb 78 [2] d4 64 }

  condition:
    any of them
}