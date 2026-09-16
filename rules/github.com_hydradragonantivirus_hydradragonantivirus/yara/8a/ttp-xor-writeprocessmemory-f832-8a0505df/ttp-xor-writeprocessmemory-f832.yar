rule TTP_XOR_WriteProcessMemory_f832 {
  strings:
    $key_f832 = { af 40 [2] 9d 62 [2] 9b 57 [2] b5 57 [2] 8a 4b }

  condition:
    any of them
}