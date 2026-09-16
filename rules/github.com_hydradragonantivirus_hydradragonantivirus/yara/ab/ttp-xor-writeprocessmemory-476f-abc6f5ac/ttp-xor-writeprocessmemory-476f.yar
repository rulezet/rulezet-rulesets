rule TTP_XOR_WriteProcessMemory_476f {
  strings:
    $key_476f = { 10 1d [2] 22 3f [2] 24 0a [2] 0a 0a [2] 35 16 }

  condition:
    any of them
}