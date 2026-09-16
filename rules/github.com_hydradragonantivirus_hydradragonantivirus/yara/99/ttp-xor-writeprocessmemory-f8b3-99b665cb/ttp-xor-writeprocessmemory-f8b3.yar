rule TTP_XOR_WriteProcessMemory_f8b3 {
  strings:
    $key_f8b3 = { af c1 [2] 9d e3 [2] 9b d6 [2] b5 d6 [2] 8a ca }

  condition:
    any of them
}