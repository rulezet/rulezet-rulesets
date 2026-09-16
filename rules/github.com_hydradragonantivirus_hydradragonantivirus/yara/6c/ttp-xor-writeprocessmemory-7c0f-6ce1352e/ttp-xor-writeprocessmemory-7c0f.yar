rule TTP_XOR_WriteProcessMemory_7c0f {
  strings:
    $key_7c0f = { 2b 7d [2] 19 5f [2] 1f 6a [2] 31 6a [2] 0e 76 }

  condition:
    any of them
}