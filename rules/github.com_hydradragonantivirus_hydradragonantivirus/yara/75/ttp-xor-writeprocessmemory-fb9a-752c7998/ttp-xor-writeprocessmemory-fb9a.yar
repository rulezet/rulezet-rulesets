rule TTP_XOR_WriteProcessMemory_fb9a {
  strings:
    $key_fb9a = { ac e8 [2] 9e ca [2] 98 ff [2] b6 ff [2] 89 e3 }

  condition:
    any of them
}