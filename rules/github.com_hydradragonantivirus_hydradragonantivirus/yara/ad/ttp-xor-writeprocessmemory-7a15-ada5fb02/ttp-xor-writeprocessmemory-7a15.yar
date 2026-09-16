rule TTP_XOR_WriteProcessMemory_7a15 {
  strings:
    $key_7a15 = { 2d 67 [2] 1f 45 [2] 19 70 [2] 37 70 [2] 08 6c }

  condition:
    any of them
}