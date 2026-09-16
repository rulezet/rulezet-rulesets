rule TTP_XOR_WriteProcessMemory_eb0f {
  strings:
    $key_eb0f = { bc 7d [2] 8e 5f [2] 88 6a [2] a6 6a [2] 99 76 }

  condition:
    any of them
}