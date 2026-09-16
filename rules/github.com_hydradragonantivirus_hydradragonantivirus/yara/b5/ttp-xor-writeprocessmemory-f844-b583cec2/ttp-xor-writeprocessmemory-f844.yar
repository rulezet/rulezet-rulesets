rule TTP_XOR_WriteProcessMemory_f844 {
  strings:
    $key_f844 = { af 36 [2] 9d 14 [2] 9b 21 [2] b5 21 [2] 8a 3d }

  condition:
    any of them
}