rule TTP_XOR_WriteProcessMemory_fb38 {
  strings:
    $key_fb38 = { ac 4a [2] 9e 68 [2] 98 5d [2] b6 5d [2] 89 41 }

  condition:
    any of them
}