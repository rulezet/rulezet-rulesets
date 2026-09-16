rule TTP_XOR_WriteProcessMemory_037f {
  strings:
    $key_037f = { 54 0d [2] 66 2f [2] 60 1a [2] 4e 1a [2] 71 06 }

  condition:
    any of them
}