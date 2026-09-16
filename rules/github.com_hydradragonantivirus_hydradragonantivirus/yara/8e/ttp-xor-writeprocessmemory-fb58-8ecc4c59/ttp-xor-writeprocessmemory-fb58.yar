rule TTP_XOR_WriteProcessMemory_fb58 {
  strings:
    $key_fb58 = { ac 2a [2] 9e 08 [2] 98 3d [2] b6 3d [2] 89 21 }

  condition:
    any of them
}