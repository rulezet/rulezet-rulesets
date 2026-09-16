rule TTP_XOR_WriteProcessMemory_8989 {
  strings:
    $key_8989 = { de fb [2] ec d9 [2] ea ec [2] c4 ec [2] fb f0 }

  condition:
    any of them
}