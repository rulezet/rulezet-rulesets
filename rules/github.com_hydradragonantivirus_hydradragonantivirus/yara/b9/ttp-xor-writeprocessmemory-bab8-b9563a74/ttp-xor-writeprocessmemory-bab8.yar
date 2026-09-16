rule TTP_XOR_WriteProcessMemory_bab8 {
  strings:
    $key_bab8 = { ed ca [2] df e8 [2] d9 dd [2] f7 dd [2] c8 c1 }

  condition:
    any of them
}