rule TTP_XOR_WriteProcessMemory_aba8 {
  strings:
    $key_aba8 = { fc da [2] ce f8 [2] c8 cd [2] e6 cd [2] d9 d1 }

  condition:
    any of them
}