rule TTP_XOR_WriteProcessMemory_fbff {
  strings:
    $key_fbff = { ac 8d [2] 9e af [2] 98 9a [2] b6 9a [2] 89 86 }

  condition:
    any of them
}