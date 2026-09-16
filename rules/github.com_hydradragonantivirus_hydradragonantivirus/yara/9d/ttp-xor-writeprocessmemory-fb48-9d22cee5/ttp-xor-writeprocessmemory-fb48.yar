rule TTP_XOR_WriteProcessMemory_fb48 {
  strings:
    $key_fb48 = { ac 3a [2] 9e 18 [2] 98 2d [2] b6 2d [2] 89 31 }

  condition:
    any of them
}