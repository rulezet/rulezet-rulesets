rule TTP_XOR_WriteProcessMemory_395f {
  strings:
    $key_395f = { 6e 2d [2] 5c 0f [2] 5a 3a [2] 74 3a [2] 4b 26 }

  condition:
    any of them
}