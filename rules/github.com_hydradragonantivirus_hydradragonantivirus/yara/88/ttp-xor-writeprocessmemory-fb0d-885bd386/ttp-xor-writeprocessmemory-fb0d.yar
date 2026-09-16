rule TTP_XOR_WriteProcessMemory_fb0d {
  strings:
    $key_fb0d = { ac 7f [2] 9e 5d [2] 98 68 [2] b6 68 [2] 89 74 }

  condition:
    any of them
}