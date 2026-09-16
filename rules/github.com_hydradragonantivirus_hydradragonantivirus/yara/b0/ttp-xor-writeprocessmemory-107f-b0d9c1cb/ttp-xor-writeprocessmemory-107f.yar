rule TTP_XOR_WriteProcessMemory_107f {
  strings:
    $key_107f = { 47 0d [2] 75 2f [2] 73 1a [2] 5d 1a [2] 62 06 }

  condition:
    any of them
}