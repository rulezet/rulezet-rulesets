rule TTP_XOR_WriteProcessMemory_3b7f {
  strings:
    $key_3b7f = { 6c 0d [2] 5e 2f [2] 58 1a [2] 76 1a [2] 49 06 }

  condition:
    any of them
}