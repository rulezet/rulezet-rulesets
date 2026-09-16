rule TTP_XOR_WriteProcessMemory_023f {
  strings:
    $key_023f = { 55 4d [2] 67 6f [2] 61 5a [2] 4f 5a [2] 70 46 }

  condition:
    any of them
}