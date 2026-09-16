rule TTP_XOR_WriteProcessMemory_2e4f {
  strings:
    $key_2e4f = { 79 3d [2] 4b 1f [2] 4d 2a [2] 63 2a [2] 5c 36 }

  condition:
    any of them
}