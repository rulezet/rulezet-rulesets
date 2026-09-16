rule TTP_XOR_WriteProcessMemory_5ae4 {
  strings:
    $key_5ae4 = { 0d 96 [2] 3f b4 [2] 39 81 [2] 17 81 [2] 28 9d }

  condition:
    any of them
}