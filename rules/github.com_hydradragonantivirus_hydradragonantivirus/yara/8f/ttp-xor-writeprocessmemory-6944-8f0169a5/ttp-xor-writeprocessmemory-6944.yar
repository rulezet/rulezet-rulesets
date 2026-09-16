rule TTP_XOR_WriteProcessMemory_6944 {
  strings:
    $key_6944 = { 3e 36 [2] 0c 14 [2] 0a 21 [2] 24 21 [2] 1b 3d }

  condition:
    any of them
}