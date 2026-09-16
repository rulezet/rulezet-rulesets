rule TTP_XOR_WriteProcessMemory_89d6 {
  strings:
    $key_89d6 = { de a4 [2] ec 86 [2] ea b3 [2] c4 b3 [2] fb af }

  condition:
    any of them
}