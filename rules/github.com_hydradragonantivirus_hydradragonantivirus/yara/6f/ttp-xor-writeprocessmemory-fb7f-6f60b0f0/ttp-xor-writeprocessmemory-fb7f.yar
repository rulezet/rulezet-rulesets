rule TTP_XOR_WriteProcessMemory_fb7f {
  strings:
    $key_fb7f = { ac 0d [2] 9e 2f [2] 98 1a [2] b6 1a [2] 89 06 }

  condition:
    any of them
}