rule TTP_XOR_WriteProcessMemory_0c4f {
  strings:
    $key_0c4f = { 5b 3d [2] 69 1f [2] 6f 2a [2] 41 2a [2] 7e 36 }

  condition:
    any of them
}