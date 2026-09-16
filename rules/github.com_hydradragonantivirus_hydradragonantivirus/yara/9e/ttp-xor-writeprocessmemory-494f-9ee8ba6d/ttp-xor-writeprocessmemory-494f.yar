rule TTP_XOR_WriteProcessMemory_494f {
  strings:
    $key_494f = { 1e 3d [2] 2c 1f [2] 2a 2a [2] 04 2a [2] 3b 36 }

  condition:
    any of them
}