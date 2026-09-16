rule TTP_XOR_WriteProcessMemory_ee52 {
  strings:
    $key_ee52 = { b9 20 [2] 8b 02 [2] 8d 37 [2] a3 37 [2] 9c 2b }

  condition:
    any of them
}