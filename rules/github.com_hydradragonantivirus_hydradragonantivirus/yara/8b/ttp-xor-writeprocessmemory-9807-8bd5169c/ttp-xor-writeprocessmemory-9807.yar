rule TTP_XOR_WriteProcessMemory_9807 {
  strings:
    $key_9807 = { cf 75 [2] fd 57 [2] fb 62 [2] d5 62 [2] ea 7e }

  condition:
    any of them
}