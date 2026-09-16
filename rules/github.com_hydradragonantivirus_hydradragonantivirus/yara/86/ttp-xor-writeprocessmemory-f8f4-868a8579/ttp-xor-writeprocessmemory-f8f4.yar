rule TTP_XOR_WriteProcessMemory_f8f4 {
  strings:
    $key_f8f4 = { af 86 [2] 9d a4 [2] 9b 91 [2] b5 91 [2] 8a 8d }

  condition:
    any of them
}