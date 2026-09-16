rule TTP_XOR_WriteProcessMemory_fb3a {
  strings:
    $key_fb3a = { ac 48 [2] 9e 6a [2] 98 5f [2] b6 5f [2] 89 43 }

  condition:
    any of them
}