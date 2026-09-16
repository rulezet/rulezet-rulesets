rule TTP_XOR_WriteProcessMemory_fca5 {
  strings:
    $key_fca5 = { ab d7 [2] 99 f5 [2] 9f c0 [2] b1 c0 [2] 8e dc }

  condition:
    any of them
}