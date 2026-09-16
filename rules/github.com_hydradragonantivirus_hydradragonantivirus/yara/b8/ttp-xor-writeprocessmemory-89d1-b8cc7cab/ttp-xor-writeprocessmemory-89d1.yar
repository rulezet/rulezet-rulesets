rule TTP_XOR_WriteProcessMemory_89d1 {
  strings:
    $key_89d1 = { de a3 [2] ec 81 [2] ea b4 [2] c4 b4 [2] fb a8 }

  condition:
    any of them
}