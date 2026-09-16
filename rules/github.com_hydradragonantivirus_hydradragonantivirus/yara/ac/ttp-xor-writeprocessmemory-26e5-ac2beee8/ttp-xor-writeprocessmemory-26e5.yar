rule TTP_XOR_WriteProcessMemory_26e5 {
  strings:
    $key_26e5 = { 71 97 [2] 43 b5 [2] 45 80 [2] 6b 80 [2] 54 9c }

  condition:
    any of them
}