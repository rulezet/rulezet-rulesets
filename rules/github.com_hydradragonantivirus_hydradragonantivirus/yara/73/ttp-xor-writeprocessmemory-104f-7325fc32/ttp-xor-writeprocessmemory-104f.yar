rule TTP_XOR_WriteProcessMemory_104f {
  strings:
    $key_104f = { 47 3d [2] 75 1f [2] 73 2a [2] 5d 2a [2] 62 36 }

  condition:
    any of them
}