rule TTP_XOR_WriteProcessMemory_f84b {
  strings:
    $key_f84b = { af 39 [2] 9d 1b [2] 9b 2e [2] b5 2e [2] 8a 32 }

  condition:
    any of them
}