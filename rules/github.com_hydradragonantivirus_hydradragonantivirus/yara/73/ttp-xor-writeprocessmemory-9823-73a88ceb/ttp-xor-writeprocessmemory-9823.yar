rule TTP_XOR_WriteProcessMemory_9823 {
  strings:
    $key_9823 = { cf 51 [2] fd 73 [2] fb 46 [2] d5 46 [2] ea 5a }

  condition:
    any of them
}