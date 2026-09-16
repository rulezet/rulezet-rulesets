rule TTP_XOR_WriteProcessMemory_d8c9 {
  strings:
    $key_d8c9 = { 8f bb [2] bd 99 [2] bb ac [2] 95 ac [2] aa b0 }

  condition:
    any of them
}