rule TTP_XOR_WriteProcessMemory_111f {
  strings:
    $key_111f = { 46 6d [2] 74 4f [2] 72 7a [2] 5c 7a [2] 63 66 }

  condition:
    any of them
}