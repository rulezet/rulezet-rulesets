rule TTP_XOR_WriteProcessMemory_3ae4 {
  strings:
    $key_3ae4 = { 6d 96 [2] 5f b4 [2] 59 81 [2] 77 81 [2] 48 9d }

  condition:
    any of them
}