rule TTP_XOR_WriteProcessMemory_fb93 {
  strings:
    $key_fb93 = { ac e1 [2] 9e c3 [2] 98 f6 [2] b6 f6 [2] 89 ea }

  condition:
    any of them
}