rule TTP_XOR_WriteProcessMemory_f94f {
  strings:
    $key_f94f = { ae 3d [2] 9c 1f [2] 9a 2a [2] b4 2a [2] 8b 36 }

  condition:
    any of them
}