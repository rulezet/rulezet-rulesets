rule TTP_XOR_WriteProcessMemory_e44d {
  strings:
    $key_e44d = { b3 3f [2] 81 1d [2] 87 28 [2] a9 28 [2] 96 34 }

  condition:
    any of them
}