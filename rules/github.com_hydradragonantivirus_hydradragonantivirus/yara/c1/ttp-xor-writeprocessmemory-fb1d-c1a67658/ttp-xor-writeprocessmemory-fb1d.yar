rule TTP_XOR_WriteProcessMemory_fb1d {
  strings:
    $key_fb1d = { ac 6f [2] 9e 4d [2] 98 78 [2] b6 78 [2] 89 64 }

  condition:
    any of them
}