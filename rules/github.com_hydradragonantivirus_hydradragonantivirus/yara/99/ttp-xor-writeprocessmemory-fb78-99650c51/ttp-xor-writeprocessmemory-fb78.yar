rule TTP_XOR_WriteProcessMemory_fb78 {
  strings:
    $key_fb78 = { ac 0a [2] 9e 28 [2] 98 1d [2] b6 1d [2] 89 01 }

  condition:
    any of them
}