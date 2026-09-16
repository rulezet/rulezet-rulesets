rule TTP_XOR_WriteProcessMemory_536f {
  strings:
    $key_536f = { 04 1d [2] 36 3f [2] 30 0a [2] 1e 0a [2] 21 16 }

  condition:
    any of them
}