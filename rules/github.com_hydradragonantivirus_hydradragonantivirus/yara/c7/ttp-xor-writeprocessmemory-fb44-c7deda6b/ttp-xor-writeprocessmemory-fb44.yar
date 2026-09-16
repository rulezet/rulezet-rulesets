rule TTP_XOR_WriteProcessMemory_fb44 {
  strings:
    $key_fb44 = { ac 36 [2] 9e 14 [2] 98 21 [2] b6 21 [2] 89 3d }

  condition:
    any of them
}