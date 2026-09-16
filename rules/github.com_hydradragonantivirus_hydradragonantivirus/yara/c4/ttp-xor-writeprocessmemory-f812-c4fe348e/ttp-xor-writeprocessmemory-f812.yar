rule TTP_XOR_WriteProcessMemory_f812 {
  strings:
    $key_f812 = { af 60 [2] 9d 42 [2] 9b 77 [2] b5 77 [2] 8a 6b }

  condition:
    any of them
}