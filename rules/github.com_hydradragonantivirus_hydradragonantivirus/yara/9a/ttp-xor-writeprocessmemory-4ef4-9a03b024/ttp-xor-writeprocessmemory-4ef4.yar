rule TTP_XOR_WriteProcessMemory_4ef4 {
  strings:
    $key_4ef4 = { 19 86 [2] 2b a4 [2] 2d 91 [2] 03 91 [2] 3c 8d }

  condition:
    any of them
}