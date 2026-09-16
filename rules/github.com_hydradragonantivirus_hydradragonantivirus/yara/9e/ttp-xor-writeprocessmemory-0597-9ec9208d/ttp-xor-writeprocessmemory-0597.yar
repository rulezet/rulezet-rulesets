rule TTP_XOR_WriteProcessMemory_0597 {
  strings:
    $key_0597 = { 52 e5 [2] 60 c7 [2] 66 f2 [2] 48 f2 [2] 77 ee }

  condition:
    any of them
}