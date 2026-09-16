rule TTP_XOR_WriteProcessMemory_143f {
  strings:
    $key_143f = { 43 4d [2] 71 6f [2] 77 5a [2] 59 5a [2] 66 46 }

  condition:
    any of them
}