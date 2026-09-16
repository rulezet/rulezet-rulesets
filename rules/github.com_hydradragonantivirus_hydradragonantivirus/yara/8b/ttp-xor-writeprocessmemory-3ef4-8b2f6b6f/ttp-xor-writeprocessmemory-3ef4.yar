rule TTP_XOR_WriteProcessMemory_3ef4 {
  strings:
    $key_3ef4 = { 69 86 [2] 5b a4 [2] 5d 91 [2] 73 91 [2] 4c 8d }

  condition:
    any of them
}