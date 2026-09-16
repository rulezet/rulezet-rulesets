rule TTP_XOR_WriteProcessMemory_fb01 {
  strings:
    $key_fb01 = { ac 73 [2] 9e 51 [2] 98 64 [2] b6 64 [2] 89 78 }

  condition:
    any of them
}