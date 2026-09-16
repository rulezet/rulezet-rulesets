rule TTP_XOR_WriteProcessMemory_120f {
  strings:
    $key_120f = { 45 7d [2] 77 5f [2] 71 6a [2] 5f 6a [2] 60 76 }

  condition:
    any of them
}