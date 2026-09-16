rule TTP_XOR_WriteProcessMemory_ee55 {
  strings:
    $key_ee55 = { b9 27 [2] 8b 05 [2] 8d 30 [2] a3 30 [2] 9c 2c }

  condition:
    any of them
}