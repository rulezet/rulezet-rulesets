rule TTP_XOR_WriteProcessMemory_eb1f {
  strings:
    $key_eb1f = { bc 6d [2] 8e 4f [2] 88 7a [2] a6 7a [2] 99 66 }

  condition:
    any of them
}