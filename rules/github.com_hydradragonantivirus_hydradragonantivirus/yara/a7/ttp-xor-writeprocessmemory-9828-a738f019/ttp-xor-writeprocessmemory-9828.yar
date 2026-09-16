rule TTP_XOR_WriteProcessMemory_9828 {
  strings:
    $key_9828 = { cf 5a [2] fd 78 [2] fb 4d [2] d5 4d [2] ea 51 }

  condition:
    any of them
}