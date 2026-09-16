rule TTP_XOR_WriteProcessMemory_012f {
  strings:
    $key_012f = { 56 5d [2] 64 7f [2] 62 4a [2] 4c 4a [2] 73 56 }

  condition:
    any of them
}