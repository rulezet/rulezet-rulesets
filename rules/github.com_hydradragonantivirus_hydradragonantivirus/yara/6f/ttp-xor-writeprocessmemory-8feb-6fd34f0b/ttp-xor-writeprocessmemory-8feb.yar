rule TTP_XOR_WriteProcessMemory_8feb {
  strings:
    $key_8feb = { d8 99 [2] ea bb [2] ec 8e [2] c2 8e [2] fd 92 }

  condition:
    any of them
}