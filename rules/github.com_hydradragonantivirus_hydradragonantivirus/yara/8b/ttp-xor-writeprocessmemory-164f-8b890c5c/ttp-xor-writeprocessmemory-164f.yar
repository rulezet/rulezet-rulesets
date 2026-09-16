rule TTP_XOR_WriteProcessMemory_164f {
  strings:
    $key_164f = { 41 3d [2] 73 1f [2] 75 2a [2] 5b 2a [2] 64 36 }

  condition:
    any of them
}