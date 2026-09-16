rule TTP_XOR_WriteProcessMemory_e814 {
  strings:
    $key_e814 = { bf 66 [2] 8d 44 [2] 8b 71 [2] a5 71 [2] 9a 6d }

  condition:
    any of them
}