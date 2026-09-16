rule TTP_XOR_WriteProcessMemory_e808 {
  strings:
    $key_e808 = { bf 7a [2] 8d 58 [2] 8b 6d [2] a5 6d [2] 9a 71 }

  condition:
    any of them
}