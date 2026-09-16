rule TTP_XOR_WriteProcessMemory_5dff {
  strings:
    $key_5dff = { 0a 8d [2] 38 af [2] 3e 9a [2] 10 9a [2] 2f 86 }

  condition:
    any of them
}