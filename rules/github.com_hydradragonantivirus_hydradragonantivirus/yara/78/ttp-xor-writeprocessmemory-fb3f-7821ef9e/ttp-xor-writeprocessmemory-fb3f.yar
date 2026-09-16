rule TTP_XOR_WriteProcessMemory_fb3f {
  strings:
    $key_fb3f = { ac 4d [2] 9e 6f [2] 98 5a [2] b6 5a [2] 89 46 }

  condition:
    any of them
}