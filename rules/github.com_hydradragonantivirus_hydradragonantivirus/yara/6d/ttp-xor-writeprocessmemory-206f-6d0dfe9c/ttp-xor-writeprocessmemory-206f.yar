rule TTP_XOR_WriteProcessMemory_206f {
  strings:
    $key_206f = { 77 1d [2] 45 3f [2] 43 0a [2] 6d 0a [2] 52 16 }

  condition:
    any of them
}