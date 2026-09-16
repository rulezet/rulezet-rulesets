rule TTP_XOR_WriteProcessMemory_6686 {
  strings:
    $key_6686 = { 31 f4 [2] 03 d6 [2] 05 e3 [2] 2b e3 [2] 14 ff }

  condition:
    any of them
}