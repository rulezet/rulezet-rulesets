rule TTP_XOR_WriteProcessMemory_ee08 {
  strings:
    $key_ee08 = { b9 7a [2] 8b 58 [2] 8d 6d [2] a3 6d [2] 9c 71 }

  condition:
    any of them
}