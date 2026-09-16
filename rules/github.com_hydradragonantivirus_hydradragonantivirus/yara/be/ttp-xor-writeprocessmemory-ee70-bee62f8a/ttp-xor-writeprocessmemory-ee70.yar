rule TTP_XOR_WriteProcessMemory_ee70 {
  strings:
    $key_ee70 = { b9 02 [2] 8b 20 [2] 8d 15 [2] a3 15 [2] 9c 09 }

  condition:
    any of them
}