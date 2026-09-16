rule TTP_XOR_WriteProcessMemory_ee48 {
  strings:
    $key_ee48 = { b9 3a [2] 8b 18 [2] 8d 2d [2] a3 2d [2] 9c 31 }

  condition:
    any of them
}