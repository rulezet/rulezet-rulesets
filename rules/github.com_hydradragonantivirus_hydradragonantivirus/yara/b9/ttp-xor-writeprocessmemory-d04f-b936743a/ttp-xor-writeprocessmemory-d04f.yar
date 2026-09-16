rule TTP_XOR_WriteProcessMemory_d04f {
  strings:
    $key_d04f = { 87 3d [2] b5 1f [2] b3 2a [2] 9d 2a [2] a2 36 }

  condition:
    any of them
}