rule TTP_XOR_WriteProcessMemory_bced {
  strings:
    $key_bced = { eb 9f [2] d9 bd [2] df 88 [2] f1 88 [2] ce 94 }

  condition:
    any of them
}