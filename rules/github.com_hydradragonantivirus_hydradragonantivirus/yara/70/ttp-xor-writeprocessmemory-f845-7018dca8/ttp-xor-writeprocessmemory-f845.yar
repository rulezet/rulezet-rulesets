rule TTP_XOR_WriteProcessMemory_f845 {
  strings:
    $key_f845 = { af 37 [2] 9d 15 [2] 9b 20 [2] b5 20 [2] 8a 3c }

  condition:
    any of them
}