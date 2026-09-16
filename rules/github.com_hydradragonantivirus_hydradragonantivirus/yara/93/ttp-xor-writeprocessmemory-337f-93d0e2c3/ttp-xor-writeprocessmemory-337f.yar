rule TTP_XOR_WriteProcessMemory_337f {
  strings:
    $key_337f = { 64 0d [2] 56 2f [2] 50 1a [2] 7e 1a [2] 41 06 }

  condition:
    any of them
}