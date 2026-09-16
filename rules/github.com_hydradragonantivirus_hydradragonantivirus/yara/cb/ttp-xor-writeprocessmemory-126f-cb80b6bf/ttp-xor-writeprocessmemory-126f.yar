rule TTP_XOR_WriteProcessMemory_126f {
  strings:
    $key_126f = { 45 1d [2] 77 3f [2] 71 0a [2] 5f 0a [2] 60 16 }

  condition:
    any of them
}