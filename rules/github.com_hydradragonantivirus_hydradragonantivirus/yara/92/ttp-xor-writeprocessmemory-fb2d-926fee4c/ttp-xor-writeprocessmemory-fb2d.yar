rule TTP_XOR_WriteProcessMemory_fb2d {
  strings:
    $key_fb2d = { ac 5f [2] 9e 7d [2] 98 48 [2] b6 48 [2] 89 54 }

  condition:
    any of them
}