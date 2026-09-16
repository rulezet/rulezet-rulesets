rule TTP_XOR_WriteProcessMemory_fff4 {
  strings:
    $key_fff4 = { a8 86 [2] 9a a4 [2] 9c 91 [2] b2 91 [2] 8d 8d }

  condition:
    any of them
}