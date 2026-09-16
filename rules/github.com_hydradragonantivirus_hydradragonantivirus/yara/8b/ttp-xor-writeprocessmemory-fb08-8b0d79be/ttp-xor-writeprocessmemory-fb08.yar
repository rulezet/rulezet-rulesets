rule TTP_XOR_WriteProcessMemory_fb08 {
  strings:
    $key_fb08 = { ac 7a [2] 9e 58 [2] 98 6d [2] b6 6d [2] 89 71 }

  condition:
    any of them
}