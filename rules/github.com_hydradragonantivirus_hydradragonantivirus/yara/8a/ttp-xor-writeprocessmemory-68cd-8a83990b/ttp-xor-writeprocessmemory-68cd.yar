rule TTP_XOR_WriteProcessMemory_68cd {
  strings:
    $key_68cd = { 3f bf [2] 0d 9d [2] 0b a8 [2] 25 a8 [2] 1a b4 }

  condition:
    any of them
}