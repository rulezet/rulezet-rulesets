rule TTP_XOR_WriteProcessMemory_5ae5 {
  strings:
    $key_5ae5 = { 0d 97 [2] 3f b5 [2] 39 80 [2] 17 80 [2] 28 9c }

  condition:
    any of them
}