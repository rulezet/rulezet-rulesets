rule TTP_XOR_WriteProcessMemory_6b0f {
  strings:
    $key_6b0f = { 3c 7d [2] 0e 5f [2] 08 6a [2] 26 6a [2] 19 76 }

  condition:
    any of them
}