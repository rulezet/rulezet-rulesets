rule TTP_XOR_WriteProcessMemory_3186 {
  strings:
    $key_3186 = { 66 f4 [2] 54 d6 [2] 52 e3 [2] 7c e3 [2] 43 ff }

  condition:
    any of them
}