rule TTP_XOR_WriteProcessMemory_fb36 {
  strings:
    $key_fb36 = { ac 44 [2] 9e 66 [2] 98 53 [2] b6 53 [2] 89 4f }

  condition:
    any of them
}