rule TTP_XOR_WriteProcessMemory_316f {
  strings:
    $key_316f = { 66 1d [2] 54 3f [2] 52 0a [2] 7c 0a [2] 43 16 }

  condition:
    any of them
}