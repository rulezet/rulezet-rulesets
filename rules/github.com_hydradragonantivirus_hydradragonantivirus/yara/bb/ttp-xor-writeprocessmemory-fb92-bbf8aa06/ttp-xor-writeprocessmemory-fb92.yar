rule TTP_XOR_WriteProcessMemory_fb92 {
  strings:
    $key_fb92 = { ac e0 [2] 9e c2 [2] 98 f7 [2] b6 f7 [2] 89 eb }

  condition:
    any of them
}