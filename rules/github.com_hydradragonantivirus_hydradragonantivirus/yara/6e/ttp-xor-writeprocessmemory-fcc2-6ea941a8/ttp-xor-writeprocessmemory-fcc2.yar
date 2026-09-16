rule TTP_XOR_WriteProcessMemory_fcc2 {
  strings:
    $key_fcc2 = { ab b0 [2] 99 92 [2] 9f a7 [2] b1 a7 [2] 8e bb }

  condition:
    any of them
}