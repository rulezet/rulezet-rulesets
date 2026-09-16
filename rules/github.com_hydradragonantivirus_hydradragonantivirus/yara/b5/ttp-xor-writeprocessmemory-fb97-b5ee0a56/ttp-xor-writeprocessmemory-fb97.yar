rule TTP_XOR_WriteProcessMemory_fb97 {
  strings:
    $key_fb97 = { ac e5 [2] 9e c7 [2] 98 f2 [2] b6 f2 [2] 89 ee }

  condition:
    any of them
}