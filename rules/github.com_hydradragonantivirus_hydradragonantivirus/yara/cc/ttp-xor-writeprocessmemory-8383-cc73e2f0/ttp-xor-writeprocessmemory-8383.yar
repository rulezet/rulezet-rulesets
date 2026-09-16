rule TTP_XOR_WriteProcessMemory_8383 {
  strings:
    $key_8383 = { d4 f1 [2] e6 d3 [2] e0 e6 [2] ce e6 [2] f1 fa }

  condition:
    any of them
}