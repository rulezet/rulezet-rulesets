rule TTP_XOR_WriteProcessMemory_bafd {
  strings:
    $key_bafd = { ed 8f [2] df ad [2] d9 98 [2] f7 98 [2] c8 84 }

  condition:
    any of them
}