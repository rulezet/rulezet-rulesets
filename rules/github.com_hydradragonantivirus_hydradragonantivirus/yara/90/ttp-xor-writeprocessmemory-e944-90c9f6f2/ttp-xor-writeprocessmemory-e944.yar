rule TTP_XOR_WriteProcessMemory_e944 {
  strings:
    $key_e944 = { be 36 [2] 8c 14 [2] 8a 21 [2] a4 21 [2] 9b 3d }

  condition:
    any of them
}