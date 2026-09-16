rule TTP_XOR_WriteProcessMemory_0814 {
  strings:
    $key_0814 = { 5f 66 [2] 6d 44 [2] 6b 71 [2] 45 71 [2] 7a 6d }

  condition:
    any of them
}