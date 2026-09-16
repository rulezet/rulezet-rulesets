rule TTP_XOR_WriteProcessMemory_6c0f {
  strings:
    $key_6c0f = { 3b 7d [2] 09 5f [2] 0f 6a [2] 21 6a [2] 1e 76 }

  condition:
    any of them
}