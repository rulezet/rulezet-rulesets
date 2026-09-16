rule TTP_XOR_WriteProcessMemory_ba0a {
  strings:
    $key_ba0a = { ed 78 [2] df 5a [2] d9 6f [2] f7 6f [2] c8 73 }

  condition:
    any of them
}