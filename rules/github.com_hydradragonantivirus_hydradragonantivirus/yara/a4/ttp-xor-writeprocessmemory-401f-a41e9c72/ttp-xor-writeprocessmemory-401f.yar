rule TTP_XOR_WriteProcessMemory_401f {
  strings:
    $key_401f = { 17 6d [2] 25 4f [2] 23 7a [2] 0d 7a [2] 32 66 }

  condition:
    any of them
}