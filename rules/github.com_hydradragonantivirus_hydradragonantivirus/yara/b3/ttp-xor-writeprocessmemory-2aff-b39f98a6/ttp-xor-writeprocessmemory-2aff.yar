rule TTP_XOR_WriteProcessMemory_2aff {
  strings:
    $key_2aff = { 7d 8d [2] 4f af [2] 49 9a [2] 67 9a [2] 58 86 }

  condition:
    any of them
}