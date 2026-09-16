rule TTP_XOR_WriteProcessMemory_ee53 {
  strings:
    $key_ee53 = { b9 21 [2] 8b 03 [2] 8d 36 [2] a3 36 [2] 9c 2a }

  condition:
    any of them
}