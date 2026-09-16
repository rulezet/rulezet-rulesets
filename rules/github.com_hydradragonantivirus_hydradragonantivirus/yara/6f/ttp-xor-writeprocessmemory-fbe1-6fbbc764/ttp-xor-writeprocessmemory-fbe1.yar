rule TTP_XOR_WriteProcessMemory_fbe1 {
  strings:
    $key_fbe1 = { ac 93 [2] 9e b1 [2] 98 84 [2] b6 84 [2] 89 98 }

  condition:
    any of them
}