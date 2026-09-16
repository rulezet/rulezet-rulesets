rule TTP_XOR_WriteProcessMemory_fcd8 {
  strings:
    $key_fcd8 = { ab aa [2] 99 88 [2] 9f bd [2] b1 bd [2] 8e a1 }

  condition:
    any of them
}