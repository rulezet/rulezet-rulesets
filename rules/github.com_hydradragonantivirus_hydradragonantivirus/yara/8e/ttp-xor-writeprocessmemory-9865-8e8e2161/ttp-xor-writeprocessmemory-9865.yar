rule TTP_XOR_WriteProcessMemory_9865 {
  strings:
    $key_9865 = { cf 17 [2] fd 35 [2] fb 00 [2] d5 00 [2] ea 1c }

  condition:
    any of them
}