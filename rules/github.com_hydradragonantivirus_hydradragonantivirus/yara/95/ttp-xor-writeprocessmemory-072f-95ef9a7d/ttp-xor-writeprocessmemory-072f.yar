rule TTP_XOR_WriteProcessMemory_072f {
  strings:
    $key_072f = { 50 5d [2] 62 7f [2] 64 4a [2] 4a 4a [2] 75 56 }

  condition:
    any of them
}