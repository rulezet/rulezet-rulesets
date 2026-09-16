rule TTP_XOR_WriteProcessMemory_fb4f {
  strings:
    $key_fb4f = { ac 3d [2] 9e 1f [2] 98 2a [2] b6 2a [2] 89 36 }

  condition:
    any of them
}