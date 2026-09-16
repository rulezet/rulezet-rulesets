rule TTP_XOR_WriteProcessMemory_ba89 {
  strings:
    $key_ba89 = { ed fb [2] df d9 [2] d9 ec [2] f7 ec [2] c8 f0 }

  condition:
    any of them
}