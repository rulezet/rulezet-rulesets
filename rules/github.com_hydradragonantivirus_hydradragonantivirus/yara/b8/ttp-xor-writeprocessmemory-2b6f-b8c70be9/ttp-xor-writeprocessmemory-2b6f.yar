rule TTP_XOR_WriteProcessMemory_2b6f {
  strings:
    $key_2b6f = { 7c 1d [2] 4e 3f [2] 48 0a [2] 66 0a [2] 59 16 }

  condition:
    any of them
}