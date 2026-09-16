rule TTP_XOR_WriteProcessMemory_737f {
  strings:
    $key_737f = { 24 0d [2] 16 2f [2] 10 1a [2] 3e 1a [2] 01 06 }

  condition:
    any of them
}