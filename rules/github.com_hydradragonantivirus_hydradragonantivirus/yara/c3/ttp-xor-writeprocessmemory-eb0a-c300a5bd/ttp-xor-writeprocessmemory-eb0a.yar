rule TTP_XOR_WriteProcessMemory_eb0a {
  strings:
    $key_eb0a = { bc 78 [2] 8e 5a [2] 88 6f [2] a6 6f [2] 99 73 }

  condition:
    any of them
}