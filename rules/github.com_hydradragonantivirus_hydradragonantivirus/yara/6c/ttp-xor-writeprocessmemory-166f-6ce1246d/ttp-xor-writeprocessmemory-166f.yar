rule TTP_XOR_WriteProcessMemory_166f {
  strings:
    $key_166f = { 41 1d [2] 73 3f [2] 75 0a [2] 5b 0a [2] 64 16 }

  condition:
    any of them
}