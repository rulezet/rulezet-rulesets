rule TTP_XOR_WriteProcessMemory_499a {
  strings:
    $key_499a = { 1e e8 [2] 2c ca [2] 2a ff [2] 04 ff [2] 3b e3 }

  condition:
    any of them
}