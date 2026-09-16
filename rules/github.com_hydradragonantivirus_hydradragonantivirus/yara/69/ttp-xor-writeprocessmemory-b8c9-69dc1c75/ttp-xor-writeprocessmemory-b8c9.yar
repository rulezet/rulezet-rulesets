rule TTP_XOR_WriteProcessMemory_b8c9 {
  strings:
    $key_b8c9 = { ef bb [2] dd 99 [2] db ac [2] f5 ac [2] ca b0 }

  condition:
    any of them
}