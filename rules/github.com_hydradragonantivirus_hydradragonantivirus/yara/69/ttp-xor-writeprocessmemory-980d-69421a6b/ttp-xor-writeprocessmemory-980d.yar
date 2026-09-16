rule TTP_XOR_WriteProcessMemory_980d {
  strings:
    $key_980d = { cf 7f [2] fd 5d [2] fb 68 [2] d5 68 [2] ea 74 }

  condition:
    any of them
}