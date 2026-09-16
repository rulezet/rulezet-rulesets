rule TTP_XOR_WriteProcessMemory_4a0f {
  strings:
    $key_4a0f = { 1d 7d [2] 2f 5f [2] 29 6a [2] 07 6a [2] 38 76 }

  condition:
    any of them
}