rule TTP_XOR_WriteProcessMemory_f841 {
  strings:
    $key_f841 = { af 33 [2] 9d 11 [2] 9b 24 [2] b5 24 [2] 8a 38 }

  condition:
    any of them
}