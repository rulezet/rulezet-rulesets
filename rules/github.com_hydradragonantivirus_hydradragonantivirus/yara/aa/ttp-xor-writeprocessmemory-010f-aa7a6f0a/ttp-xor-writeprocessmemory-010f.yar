rule TTP_XOR_WriteProcessMemory_010f {
  strings:
    $key_010f = { 56 7d [2] 64 5f [2] 62 6a [2] 4c 6a [2] 73 76 }

  condition:
    any of them
}