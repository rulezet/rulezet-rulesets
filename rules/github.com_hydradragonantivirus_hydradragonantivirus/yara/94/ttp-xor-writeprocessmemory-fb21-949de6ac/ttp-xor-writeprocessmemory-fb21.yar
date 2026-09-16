rule TTP_XOR_WriteProcessMemory_fb21 {
  strings:
    $key_fb21 = { ac 53 [2] 9e 71 [2] 98 44 [2] b6 44 [2] 89 58 }

  condition:
    any of them
}