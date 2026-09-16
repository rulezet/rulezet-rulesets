rule TTP_XOR_WriteProcessMemory_7c7f {
  strings:
    $key_7c7f = { 2b 0d [2] 19 2f [2] 1f 1a [2] 31 1a [2] 0e 06 }

  condition:
    any of them
}