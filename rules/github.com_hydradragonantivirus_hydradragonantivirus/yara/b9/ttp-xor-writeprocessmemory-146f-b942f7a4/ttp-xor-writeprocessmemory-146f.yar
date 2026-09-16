rule TTP_XOR_WriteProcessMemory_146f {
  strings:
    $key_146f = { 43 1d [2] 71 3f [2] 77 0a [2] 59 0a [2] 66 16 }

  condition:
    any of them
}