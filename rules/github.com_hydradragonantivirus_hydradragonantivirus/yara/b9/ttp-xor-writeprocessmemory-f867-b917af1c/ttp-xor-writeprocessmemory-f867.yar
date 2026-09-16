rule TTP_XOR_WriteProcessMemory_f867 {
  strings:
    $key_f867 = { af 15 [2] 9d 37 [2] 9b 02 [2] b5 02 [2] 8a 1e }

  condition:
    any of them
}