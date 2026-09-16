rule TTP_XOR_WriteProcessMemory_422f {
  strings:
    $key_422f = { 15 5d [2] 27 7f [2] 21 4a [2] 0f 4a [2] 30 56 }

  condition:
    any of them
}