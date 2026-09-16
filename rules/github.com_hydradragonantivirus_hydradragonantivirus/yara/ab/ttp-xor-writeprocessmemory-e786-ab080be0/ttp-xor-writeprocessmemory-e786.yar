rule TTP_XOR_WriteProcessMemory_e786 {
  strings:
    $key_e786 = { b0 f4 [2] 82 d6 [2] 84 e3 [2] aa e3 [2] 95 ff }

  condition:
    any of them
}