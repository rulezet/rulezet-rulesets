rule TTP_XOR_WriteProcessMemory_1bff {
  strings:
    $key_1bff = { 4c 8d [2] 7e af [2] 78 9a [2] 56 9a [2] 69 86 }

  condition:
    any of them
}