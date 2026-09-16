rule TTP_XOR_WriteProcessMemory_e392 {
  strings:
    $key_e392 = { b4 e0 [2] 86 c2 [2] 80 f7 [2] ae f7 [2] 91 eb }

  condition:
    any of them
}