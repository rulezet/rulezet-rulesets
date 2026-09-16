rule TTP_XOR_WriteProcessMemory_7ef4 {
  strings:
    $key_7ef4 = { 29 86 [2] 1b a4 [2] 1d 91 [2] 33 91 [2] 0c 8d }

  condition:
    any of them
}