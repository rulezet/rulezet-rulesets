rule TTP_XOR_WriteProcessMemory_9893 {
  strings:
    $key_9893 = { cf e1 [2] fd c3 [2] fb f6 [2] d5 f6 [2] ea ea }

  condition:
    any of them
}