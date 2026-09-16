rule TTP_XOR_WriteProcessMemory_013f {
  strings:
    $key_013f = { 56 4d [2] 64 6f [2] 62 5a [2] 4c 5a [2] 73 46 }

  condition:
    any of them
}