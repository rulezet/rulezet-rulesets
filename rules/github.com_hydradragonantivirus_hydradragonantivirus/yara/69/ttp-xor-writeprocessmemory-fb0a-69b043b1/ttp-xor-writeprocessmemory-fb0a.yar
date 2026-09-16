rule TTP_XOR_WriteProcessMemory_fb0a {
  strings:
    $key_fb0a = { ac 78 [2] 9e 5a [2] 98 6f [2] b6 6f [2] 89 73 }

  condition:
    any of them
}