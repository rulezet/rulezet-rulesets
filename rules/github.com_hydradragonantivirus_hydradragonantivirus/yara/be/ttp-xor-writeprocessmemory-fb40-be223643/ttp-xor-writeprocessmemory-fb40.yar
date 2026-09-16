rule TTP_XOR_WriteProcessMemory_fb40 {
  strings:
    $key_fb40 = { ac 32 [2] 9e 10 [2] 98 25 [2] b6 25 [2] 89 39 }

  condition:
    any of them
}