rule TTP_XOR_WriteProcessMemory_eb7f {
  strings:
    $key_eb7f = { bc 0d [2] 8e 2f [2] 88 1a [2] a6 1a [2] 99 06 }

  condition:
    any of them
}