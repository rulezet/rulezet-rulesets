rule TTP_XOR_WriteProcessMemory_eb5a {
  strings:
    $key_eb5a = { bc 28 [2] 8e 0a [2] 88 3f [2] a6 3f [2] 99 23 }

  condition:
    any of them
}