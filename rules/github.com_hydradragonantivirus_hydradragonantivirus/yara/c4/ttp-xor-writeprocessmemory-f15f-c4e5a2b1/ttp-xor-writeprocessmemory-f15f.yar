rule TTP_XOR_WriteProcessMemory_f15f {
  strings:
    $key_f15f = { a6 2d [2] 94 0f [2] 92 3a [2] bc 3a [2] 83 26 }

  condition:
    any of them
}