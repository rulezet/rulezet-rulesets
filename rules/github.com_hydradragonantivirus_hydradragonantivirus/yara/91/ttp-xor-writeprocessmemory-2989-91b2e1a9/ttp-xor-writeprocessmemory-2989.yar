rule TTP_XOR_WriteProcessMemory_2989 {
  strings:
    $key_2989 = { 7e fb [2] 4c d9 [2] 4a ec [2] 64 ec [2] 5b f0 }

  condition:
    any of them
}