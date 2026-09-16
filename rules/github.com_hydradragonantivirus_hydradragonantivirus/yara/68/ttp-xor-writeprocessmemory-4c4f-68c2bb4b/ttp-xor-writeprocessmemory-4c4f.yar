rule TTP_XOR_WriteProcessMemory_4c4f {
  strings:
    $key_4c4f = { 1b 3d [2] 29 1f [2] 2f 2a [2] 01 2a [2] 3e 36 }

  condition:
    any of them
}