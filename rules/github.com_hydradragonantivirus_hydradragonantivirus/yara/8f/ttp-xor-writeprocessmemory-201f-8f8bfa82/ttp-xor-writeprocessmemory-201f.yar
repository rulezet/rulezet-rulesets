rule TTP_XOR_WriteProcessMemory_201f {
  strings:
    $key_201f = { 77 6d [2] 45 4f [2] 43 7a [2] 6d 7a [2] 52 66 }

  condition:
    any of them
}