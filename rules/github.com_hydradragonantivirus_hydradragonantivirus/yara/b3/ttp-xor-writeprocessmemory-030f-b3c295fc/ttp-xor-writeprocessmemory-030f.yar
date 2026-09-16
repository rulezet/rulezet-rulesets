rule TTP_XOR_WriteProcessMemory_030f {
  strings:
    $key_030f = { 54 7d [2] 66 5f [2] 60 6a [2] 4e 6a [2] 71 76 }

  condition:
    any of them
}