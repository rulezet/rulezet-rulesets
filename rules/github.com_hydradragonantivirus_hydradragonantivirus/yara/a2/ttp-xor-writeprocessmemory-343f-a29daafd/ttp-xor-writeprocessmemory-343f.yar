rule TTP_XOR_WriteProcessMemory_343f {
  strings:
    $key_343f = { 63 4d [2] 51 6f [2] 57 5a [2] 79 5a [2] 46 46 }

  condition:
    any of them
}