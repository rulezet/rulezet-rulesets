rule TTP_XOR_WriteProcessMemory_9866 {
  strings:
    $key_9866 = { cf 14 [2] fd 36 [2] fb 03 [2] d5 03 [2] ea 1f }

  condition:
    any of them
}