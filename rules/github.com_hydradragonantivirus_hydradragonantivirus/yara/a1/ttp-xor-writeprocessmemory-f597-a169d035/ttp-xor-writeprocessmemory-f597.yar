rule TTP_XOR_WriteProcessMemory_f597 {
  strings:
    $key_f597 = { a2 e5 [2] 90 c7 [2] 96 f2 [2] b8 f2 [2] 87 ee }

  condition:
    any of them
}