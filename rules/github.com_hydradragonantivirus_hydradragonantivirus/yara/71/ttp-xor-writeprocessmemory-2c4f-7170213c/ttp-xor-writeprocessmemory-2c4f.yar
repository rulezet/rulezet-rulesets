rule TTP_XOR_WriteProcessMemory_2c4f {
  strings:
    $key_2c4f = { 7b 3d [2] 49 1f [2] 4f 2a [2] 61 2a [2] 5e 36 }

  condition:
    any of them
}