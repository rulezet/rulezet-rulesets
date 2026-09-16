rule TTP_XOR_WriteProcessMemory_ba85 {
  strings:
    $key_ba85 = { ed f7 [2] df d5 [2] d9 e0 [2] f7 e0 [2] c8 fc }

  condition:
    any of them
}