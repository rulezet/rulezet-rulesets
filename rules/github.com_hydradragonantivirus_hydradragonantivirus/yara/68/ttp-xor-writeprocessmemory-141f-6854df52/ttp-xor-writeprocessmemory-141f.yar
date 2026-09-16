rule TTP_XOR_WriteProcessMemory_141f {
  strings:
    $key_141f = { 43 6d [2] 71 4f [2] 77 7a [2] 59 7a [2] 66 66 }

  condition:
    any of them
}