rule TTP_XOR_WriteProcessMemory_730f {
  strings:
    $key_730f = { 24 7d [2] 16 5f [2] 10 6a [2] 3e 6a [2] 01 76 }

  condition:
    any of them
}