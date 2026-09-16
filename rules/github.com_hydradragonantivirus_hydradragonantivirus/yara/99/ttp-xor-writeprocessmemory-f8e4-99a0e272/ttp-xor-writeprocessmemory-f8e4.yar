rule TTP_XOR_WriteProcessMemory_f8e4 {
  strings:
    $key_f8e4 = { af 96 [2] 9d b4 [2] 9b 81 [2] b5 81 [2] 8a 9d }

  condition:
    any of them
}