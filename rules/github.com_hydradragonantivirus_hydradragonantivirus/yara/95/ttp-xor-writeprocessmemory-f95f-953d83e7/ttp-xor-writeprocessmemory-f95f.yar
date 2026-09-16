rule TTP_XOR_WriteProcessMemory_f95f {
  strings:
    $key_f95f = { ae 2d [2] 9c 0f [2] 9a 3a [2] b4 3a [2] 8b 26 }

  condition:
    any of them
}