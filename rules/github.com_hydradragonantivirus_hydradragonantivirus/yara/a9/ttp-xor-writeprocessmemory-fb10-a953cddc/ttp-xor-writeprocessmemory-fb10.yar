rule TTP_XOR_WriteProcessMemory_fb10 {
  strings:
    $key_fb10 = { ac 62 [2] 9e 40 [2] 98 75 [2] b6 75 [2] 89 69 }

  condition:
    any of them
}