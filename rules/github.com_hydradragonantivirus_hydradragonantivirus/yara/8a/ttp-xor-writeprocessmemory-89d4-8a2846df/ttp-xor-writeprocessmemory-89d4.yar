rule TTP_XOR_WriteProcessMemory_89d4 {
  strings:
    $key_89d4 = { de a6 [2] ec 84 [2] ea b1 [2] c4 b1 [2] fb ad }

  condition:
    any of them
}