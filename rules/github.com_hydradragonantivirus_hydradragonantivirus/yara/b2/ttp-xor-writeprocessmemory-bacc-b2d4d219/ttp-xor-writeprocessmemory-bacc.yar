rule TTP_XOR_WriteProcessMemory_bacc {
  strings:
    $key_bacc = { ed be [2] df 9c [2] d9 a9 [2] f7 a9 [2] c8 b5 }

  condition:
    any of them
}