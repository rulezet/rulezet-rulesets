rule TTP_XOR_WriteProcessMemory_ee60 {
  strings:
    $key_ee60 = { b9 12 [2] 8b 30 [2] 8d 05 [2] a3 05 [2] 9c 19 }

  condition:
    any of them
}