rule TTP_XOR_WriteProcessMemory_c4ff {
  strings:
    $key_c4ff = { 93 8d [2] a1 af [2] a7 9a [2] 89 9a [2] b6 86 }

  condition:
    any of them
}