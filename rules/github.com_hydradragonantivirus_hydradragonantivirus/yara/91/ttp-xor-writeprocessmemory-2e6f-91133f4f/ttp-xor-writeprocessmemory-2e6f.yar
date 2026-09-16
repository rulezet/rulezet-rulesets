rule TTP_XOR_WriteProcessMemory_2e6f {
  strings:
    $key_2e6f = { 79 1d [2] 4b 3f [2] 4d 0a [2] 63 0a [2] 5c 16 }

  condition:
    any of them
}