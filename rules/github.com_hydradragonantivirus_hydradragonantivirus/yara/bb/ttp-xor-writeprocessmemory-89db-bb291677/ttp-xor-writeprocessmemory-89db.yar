rule TTP_XOR_WriteProcessMemory_89db {
  strings:
    $key_89db = { de a9 [2] ec 8b [2] ea be [2] c4 be [2] fb a2 }

  condition:
    any of them
}