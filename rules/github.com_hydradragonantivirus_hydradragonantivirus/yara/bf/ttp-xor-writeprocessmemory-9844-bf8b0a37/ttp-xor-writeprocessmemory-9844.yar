rule TTP_XOR_WriteProcessMemory_9844 {
  strings:
    $key_9844 = { cf 36 [2] fd 14 [2] fb 21 [2] d5 21 [2] ea 3d }

  condition:
    any of them
}