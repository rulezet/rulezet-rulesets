rule TTP_XOR_WriteProcessMemory_eb6f {
  strings:
    $key_eb6f = { bc 1d [2] 8e 3f [2] 88 0a [2] a6 0a [2] 99 16 }

  condition:
    any of them
}