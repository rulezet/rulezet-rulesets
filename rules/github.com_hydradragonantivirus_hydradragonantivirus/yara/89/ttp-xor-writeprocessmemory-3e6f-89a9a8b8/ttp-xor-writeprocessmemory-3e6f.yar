rule TTP_XOR_WriteProcessMemory_3e6f {
  strings:
    $key_3e6f = { 69 1d [2] 5b 3f [2] 5d 0a [2] 73 0a [2] 4c 16 }

  condition:
    any of them
}