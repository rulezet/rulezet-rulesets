rule TTP_XOR_WriteProcessMemory_f814 {
  strings:
    $key_f814 = { af 66 [2] 9d 44 [2] 9b 71 [2] b5 71 [2] 8a 6d }

  condition:
    any of them
}