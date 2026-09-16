rule TTP_XOR_WriteProcessMemory_8f15 {
  strings:
    $key_8f15 = { d8 67 [2] ea 45 [2] ec 70 [2] c2 70 [2] fd 6c }

  condition:
    any of them
}