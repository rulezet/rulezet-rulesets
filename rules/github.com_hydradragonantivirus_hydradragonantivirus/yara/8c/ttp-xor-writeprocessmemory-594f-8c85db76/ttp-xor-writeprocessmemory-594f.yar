rule TTP_XOR_WriteProcessMemory_594f {
  strings:
    $key_594f = { 0e 3d [2] 3c 1f [2] 3a 2a [2] 14 2a [2] 2b 36 }

  condition:
    any of them
}