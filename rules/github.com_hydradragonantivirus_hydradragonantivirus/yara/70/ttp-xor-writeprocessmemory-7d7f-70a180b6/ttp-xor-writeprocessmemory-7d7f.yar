rule TTP_XOR_WriteProcessMemory_7d7f {
  strings:
    $key_7d7f = { 2a 0d [2] 18 2f [2] 1e 1a [2] 30 1a [2] 0f 06 }

  condition:
    any of them
}