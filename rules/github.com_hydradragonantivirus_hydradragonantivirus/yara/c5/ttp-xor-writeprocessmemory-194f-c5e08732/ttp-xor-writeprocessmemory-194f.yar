rule TTP_XOR_WriteProcessMemory_194f {
  strings:
    $key_194f = { 4e 3d [2] 7c 1f [2] 7a 2a [2] 54 2a [2] 6b 36 }

  condition:
    any of them
}