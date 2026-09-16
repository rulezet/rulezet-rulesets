rule TTP_XOR_WriteProcessMemory_e193 {
  strings:
    $key_e193 = { b6 e1 [2] 84 c3 [2] 82 f6 [2] ac f6 [2] 93 ea }

  condition:
    any of them
}