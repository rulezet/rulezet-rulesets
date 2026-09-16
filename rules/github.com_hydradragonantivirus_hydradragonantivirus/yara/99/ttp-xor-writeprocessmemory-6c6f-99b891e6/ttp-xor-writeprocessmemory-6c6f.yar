rule TTP_XOR_WriteProcessMemory_6c6f {
  strings:
    $key_6c6f = { 3b 1d [2] 09 3f [2] 0f 0a [2] 21 0a [2] 1e 16 }

  condition:
    any of them
}