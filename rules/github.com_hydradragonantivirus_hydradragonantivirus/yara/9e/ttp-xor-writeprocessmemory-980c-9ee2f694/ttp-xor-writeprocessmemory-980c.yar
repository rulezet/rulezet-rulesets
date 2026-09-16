rule TTP_XOR_WriteProcessMemory_980c {
  strings:
    $key_980c = { cf 7e [2] fd 5c [2] fb 69 [2] d5 69 [2] ea 75 }

  condition:
    any of them
}