rule TTP_XOR_WriteProcessMemory_eb3f {
  strings:
    $key_eb3f = { bc 4d [2] 8e 6f [2] 88 5a [2] a6 5a [2] 99 46 }

  condition:
    any of them
}