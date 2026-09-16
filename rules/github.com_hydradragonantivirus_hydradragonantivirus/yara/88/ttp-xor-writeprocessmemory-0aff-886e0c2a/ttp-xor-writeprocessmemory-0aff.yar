rule TTP_XOR_WriteProcessMemory_0aff {
  strings:
    $key_0aff = { 5d 8d [2] 6f af [2] 69 9a [2] 47 9a [2] 78 86 }

  condition:
    any of them
}