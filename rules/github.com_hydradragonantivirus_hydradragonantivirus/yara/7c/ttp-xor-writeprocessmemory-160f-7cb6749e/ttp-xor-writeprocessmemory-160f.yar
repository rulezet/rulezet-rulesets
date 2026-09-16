rule TTP_XOR_WriteProcessMemory_160f {
  strings:
    $key_160f = { 41 7d [2] 73 5f [2] 75 6a [2] 5b 6a [2] 64 76 }

  condition:
    any of them
}