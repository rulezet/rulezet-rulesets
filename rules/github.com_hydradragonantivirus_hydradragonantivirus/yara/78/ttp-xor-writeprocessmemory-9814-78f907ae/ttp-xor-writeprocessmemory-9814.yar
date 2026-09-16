rule TTP_XOR_WriteProcessMemory_9814 {
  strings:
    $key_9814 = { cf 66 [2] fd 44 [2] fb 71 [2] d5 71 [2] ea 6d }

  condition:
    any of them
}