rule TTP_XOR_WriteProcessMemory_8fee {
  strings:
    $key_8fee = { d8 9c [2] ea be [2] ec 8b [2] c2 8b [2] fd 97 }

  condition:
    any of them
}