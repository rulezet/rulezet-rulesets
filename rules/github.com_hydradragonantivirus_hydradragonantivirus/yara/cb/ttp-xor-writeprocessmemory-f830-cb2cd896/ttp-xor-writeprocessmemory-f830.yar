rule TTP_XOR_WriteProcessMemory_f830 {
  strings:
    $key_f830 = { af 42 [2] 9d 60 [2] 9b 55 [2] b5 55 [2] 8a 49 }

  condition:
    any of them
}