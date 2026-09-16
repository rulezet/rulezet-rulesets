rule TTP_XOR_WriteProcessMemory_369c {
  strings:
    $key_369c = { 61 ee [2] 53 cc [2] 55 f9 [2] 7b f9 [2] 44 e5 }

  condition:
    any of them
}