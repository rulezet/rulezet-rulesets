rule TTP_XOR_WriteProcessMemory_5b0f {
  strings:
    $key_5b0f = { 0c 7d [2] 3e 5f [2] 38 6a [2] 16 6a [2] 29 76 }

  condition:
    any of them
}