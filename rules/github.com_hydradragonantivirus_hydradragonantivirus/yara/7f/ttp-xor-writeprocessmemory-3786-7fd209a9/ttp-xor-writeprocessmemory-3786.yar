rule TTP_XOR_WriteProcessMemory_3786 {
  strings:
    $key_3786 = { 60 f4 [2] 52 d6 [2] 54 e3 [2] 7a e3 [2] 45 ff }

  condition:
    any of them
}