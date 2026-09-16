rule TTP_XOR_WriteProcessMemory_9891 {
  strings:
    $key_9891 = { cf e3 [2] fd c1 [2] fb f4 [2] d5 f4 [2] ea e8 }

  condition:
    any of them
}