rule TTP_XOR_WriteProcessMemory_caff {
  strings:
    $key_caff = { 9d 8d [2] af af [2] a9 9a [2] 87 9a [2] b8 86 }

  condition:
    any of them
}