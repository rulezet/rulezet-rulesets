rule TTP_XOR_WriteProcessMemory_f857 {
  strings:
    $key_f857 = { af 25 [2] 9d 07 [2] 9b 32 [2] b5 32 [2] 8a 2e }

  condition:
    any of them
}