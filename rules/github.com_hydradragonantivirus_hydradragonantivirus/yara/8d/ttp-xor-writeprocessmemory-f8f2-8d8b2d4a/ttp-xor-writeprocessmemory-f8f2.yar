rule TTP_XOR_WriteProcessMemory_f8f2 {
  strings:
    $key_f8f2 = { af 80 [2] 9d a2 [2] 9b 97 [2] b5 97 [2] 8a 8b }

  condition:
    any of them
}