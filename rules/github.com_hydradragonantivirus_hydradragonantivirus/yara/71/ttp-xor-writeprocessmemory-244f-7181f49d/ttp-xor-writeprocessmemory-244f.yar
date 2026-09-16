rule TTP_XOR_WriteProcessMemory_244f {
  strings:
    $key_244f = { 73 3d [2] 41 1f [2] 47 2a [2] 69 2a [2] 56 36 }

  condition:
    any of them
}