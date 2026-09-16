rule TTP_XOR_WriteProcessMemory_0ef4 {
  strings:
    $key_0ef4 = { 59 86 [2] 6b a4 [2] 6d 91 [2] 43 91 [2] 7c 8d }

  condition:
    any of them
}