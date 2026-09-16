rule TTP_XOR_WriteProcessMemory_fb60 {
  strings:
    $key_fb60 = { ac 12 [2] 9e 30 [2] 98 05 [2] b6 05 [2] 89 19 }

  condition:
    any of them
}