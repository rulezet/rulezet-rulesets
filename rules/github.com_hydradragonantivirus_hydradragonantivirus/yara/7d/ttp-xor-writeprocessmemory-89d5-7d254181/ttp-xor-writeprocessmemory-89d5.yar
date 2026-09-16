rule TTP_XOR_WriteProcessMemory_89d5 {
  strings:
    $key_89d5 = { de a7 [2] ec 85 [2] ea b0 [2] c4 b0 [2] fb ac }

  condition:
    any of them
}