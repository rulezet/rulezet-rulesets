rule TTP_XOR_WriteProcessMemory_017f {
  strings:
    $key_017f = { 56 0d [2] 64 2f [2] 62 1a [2] 4c 1a [2] 73 06 }

  condition:
    any of them
}