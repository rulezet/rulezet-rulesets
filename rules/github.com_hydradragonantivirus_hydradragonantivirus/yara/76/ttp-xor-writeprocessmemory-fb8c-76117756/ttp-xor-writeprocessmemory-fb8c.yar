rule TTP_XOR_WriteProcessMemory_fb8c {
  strings:
    $key_fb8c = { ac fe [2] 9e dc [2] 98 e9 [2] b6 e9 [2] 89 f5 }

  condition:
    any of them
}