rule TTP_XOR_WriteProcessMemory_9801 {
  strings:
    $key_9801 = { cf 73 [2] fd 51 [2] fb 64 [2] d5 64 [2] ea 78 }

  condition:
    any of them
}