rule TTP_XOR_WriteProcessMemory_f8e6 {
  strings:
    $key_f8e6 = { af 94 [2] 9d b6 [2] 9b 83 [2] b5 83 [2] 8a 9f }

  condition:
    any of them
}