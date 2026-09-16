rule TTP_XOR_WriteProcessMemory_367f {
  strings:
    $key_367f = { 61 0d [2] 53 2f [2] 55 1a [2] 7b 1a [2] 44 06 }

  condition:
    any of them
}