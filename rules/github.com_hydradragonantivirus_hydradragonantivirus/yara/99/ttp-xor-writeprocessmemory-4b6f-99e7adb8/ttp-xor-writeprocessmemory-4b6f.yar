rule TTP_XOR_WriteProcessMemory_4b6f {
  strings:
    $key_4b6f = { 1c 1d [2] 2e 3f [2] 28 0a [2] 06 0a [2] 39 16 }

  condition:
    any of them
}