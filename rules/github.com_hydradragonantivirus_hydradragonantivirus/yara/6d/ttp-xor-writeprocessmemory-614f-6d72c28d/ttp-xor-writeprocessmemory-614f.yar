rule TTP_XOR_WriteProcessMemory_614f {
  strings:
    $key_614f = { 36 3d [2] 04 1f [2] 02 2a [2] 2c 2a [2] 13 36 }

  condition:
    any of them
}