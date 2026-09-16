rule TTP_XOR_WriteProcessMemory_297f {
  strings:
    $key_297f = { 7e 0d [2] 4c 2f [2] 4a 1a [2] 64 1a [2] 5b 06 }

  condition:
    any of them
}