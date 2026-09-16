rule TTP_XOR_WriteProcessMemory_badb {
  strings:
    $key_badb = { ed a9 [2] df 8b [2] d9 be [2] f7 be [2] c8 a2 }

  condition:
    any of them
}