rule TTP_XOR_WriteProcessMemory_fb9c {
  strings:
    $key_fb9c = { ac ee [2] 9e cc [2] 98 f9 [2] b6 f9 [2] 89 e5 }

  condition:
    any of them
}