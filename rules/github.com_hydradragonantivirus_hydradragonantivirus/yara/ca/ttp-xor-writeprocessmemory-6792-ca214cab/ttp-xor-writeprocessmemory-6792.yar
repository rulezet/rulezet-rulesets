rule TTP_XOR_WriteProcessMemory_6792 {
  strings:
    $key_6792 = { 30 e0 [2] 02 c2 [2] 04 f7 [2] 2a f7 [2] 15 eb }

  condition:
    any of them
}