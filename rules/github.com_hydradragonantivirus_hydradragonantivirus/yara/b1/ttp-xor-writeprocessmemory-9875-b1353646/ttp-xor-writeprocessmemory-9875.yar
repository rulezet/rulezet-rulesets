rule TTP_XOR_WriteProcessMemory_9875 {
  strings:
    $key_9875 = { cf 07 [2] fd 25 [2] fb 10 [2] d5 10 [2] ea 0c }

  condition:
    any of them
}