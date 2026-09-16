rule TTP_XOR_WriteProcessMemory_f944 {
  strings:
    $key_f944 = { ae 36 [2] 9c 14 [2] 9a 21 [2] b4 21 [2] 8b 3d }

  condition:
    any of them
}