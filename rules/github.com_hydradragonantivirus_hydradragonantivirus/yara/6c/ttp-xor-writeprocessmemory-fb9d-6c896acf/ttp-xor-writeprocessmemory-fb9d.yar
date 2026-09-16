rule TTP_XOR_WriteProcessMemory_fb9d {
  strings:
    $key_fb9d = { ac ef [2] 9e cd [2] 98 f8 [2] b6 f8 [2] 89 e4 }

  condition:
    any of them
}