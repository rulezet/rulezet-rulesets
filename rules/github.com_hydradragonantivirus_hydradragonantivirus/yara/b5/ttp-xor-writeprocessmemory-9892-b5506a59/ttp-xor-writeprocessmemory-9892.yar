rule TTP_XOR_WriteProcessMemory_9892 {
  strings:
    $key_9892 = { cf e0 [2] fd c2 [2] fb f7 [2] d5 f7 [2] ea eb }

  condition:
    any of them
}