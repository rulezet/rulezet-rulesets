rule TTP_XOR_WriteProcessMemory_4186 {
  strings:
    $key_4186 = { 16 f4 [2] 24 d6 [2] 22 e3 [2] 0c e3 [2] 33 ff }

  condition:
    any of them
}