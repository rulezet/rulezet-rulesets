rule TTP_XOR_WriteProcessMemory_fb6d {
  strings:
    $key_fb6d = { ac 1f [2] 9e 3d [2] 98 08 [2] b6 08 [2] 89 14 }

  condition:
    any of them
}