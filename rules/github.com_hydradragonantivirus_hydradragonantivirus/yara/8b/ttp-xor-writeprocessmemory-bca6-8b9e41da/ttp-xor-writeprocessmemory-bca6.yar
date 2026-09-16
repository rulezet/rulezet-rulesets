rule TTP_XOR_WriteProcessMemory_bca6 {
  strings:
    $key_bca6 = { eb d4 [2] d9 f6 [2] df c3 [2] f1 c3 [2] ce df }

  condition:
    any of them
}