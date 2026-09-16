rule TTP_XOR_WriteProcessMemory_f254 {
  strings:
    $key_f254 = { a5 26 [2] 97 04 [2] 91 31 [2] bf 31 [2] 80 2d }

  condition:
    any of them
}