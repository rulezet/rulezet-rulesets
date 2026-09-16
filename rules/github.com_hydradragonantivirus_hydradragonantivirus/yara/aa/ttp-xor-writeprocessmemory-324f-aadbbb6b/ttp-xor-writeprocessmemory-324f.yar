rule TTP_XOR_WriteProcessMemory_324f {
  strings:
    $key_324f = { 65 3d [2] 57 1f [2] 51 2a [2] 7f 2a [2] 40 36 }

  condition:
    any of them
}