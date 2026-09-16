rule TTP_XOR_WriteProcessMemory_f8f5 {
  strings:
    $key_f8f5 = { af 87 [2] 9d a5 [2] 9b 90 [2] b5 90 [2] 8a 8c }

  condition:
    any of them
}