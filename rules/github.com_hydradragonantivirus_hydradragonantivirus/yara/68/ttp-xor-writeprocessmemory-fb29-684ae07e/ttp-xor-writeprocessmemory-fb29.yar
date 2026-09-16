rule TTP_XOR_WriteProcessMemory_fb29 {
  strings:
    $key_fb29 = { ac 5b [2] 9e 79 [2] 98 4c [2] b6 4c [2] 89 50 }

  condition:
    any of them
}