rule TTP_XOR_WriteProcessMemory_6ef4 {
  strings:
    $key_6ef4 = { 39 86 [2] 0b a4 [2] 0d 91 [2] 23 91 [2] 1c 8d }

  condition:
    any of them
}