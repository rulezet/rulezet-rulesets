rule TTP_XOR_WriteProcessMemory_8f93 {
  strings:
    $key_8f93 = { d8 e1 [2] ea c3 [2] ec f6 [2] c2 f6 [2] fd ea }

  condition:
    any of them
}