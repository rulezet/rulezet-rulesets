rule TTP_XOR_WriteProcessMemory_9839 {
  strings:
    $key_9839 = { cf 4b [2] fd 69 [2] fb 5c [2] d5 5c [2] ea 40 }

  condition:
    any of them
}