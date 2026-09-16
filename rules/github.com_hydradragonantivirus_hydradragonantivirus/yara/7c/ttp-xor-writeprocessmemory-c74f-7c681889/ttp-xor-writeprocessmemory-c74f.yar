rule TTP_XOR_WriteProcessMemory_c74f {
  strings:
    $key_c74f = { 90 3d [2] a2 1f [2] a4 2a [2] 8a 2a [2] b5 36 }

  condition:
    any of them
}