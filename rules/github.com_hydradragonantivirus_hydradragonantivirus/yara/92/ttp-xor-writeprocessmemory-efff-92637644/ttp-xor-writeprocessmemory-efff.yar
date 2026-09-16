rule TTP_XOR_WriteProcessMemory_efff {
  strings:
    $key_efff = { b8 8d [2] 8a af [2] 8c 9a [2] a2 9a [2] 9d 86 }

  condition:
    any of them
}