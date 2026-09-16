rule TTP_XOR_WriteProcessMemory_122f {
  strings:
    $key_122f = { 45 5d [2] 77 7f [2] 71 4a [2] 5f 4a [2] 60 56 }

  condition:
    any of them
}