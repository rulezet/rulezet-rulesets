rule TTP_XOR_WriteProcessMemory_58f4 {
  strings:
    $key_58f4 = { 0f 86 [2] 3d a4 [2] 3b 91 [2] 15 91 [2] 2a 8d }

  condition:
    any of them
}