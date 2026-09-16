rule TTP_XOR_WriteProcessMemory_ba8d {
  strings:
    $key_ba8d = { ed ff [2] df dd [2] d9 e8 [2] f7 e8 [2] c8 f4 }

  condition:
    any of them
}