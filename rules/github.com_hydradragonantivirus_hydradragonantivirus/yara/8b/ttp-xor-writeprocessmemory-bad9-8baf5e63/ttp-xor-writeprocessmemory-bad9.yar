rule TTP_XOR_WriteProcessMemory_bad9 {
  strings:
    $key_bad9 = { ed ab [2] df 89 [2] d9 bc [2] f7 bc [2] c8 a0 }

  condition:
    any of them
}