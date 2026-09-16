rule TTP_XOR_WriteProcessMemory_369a {
  strings:
    $key_369a = { 61 e8 [2] 53 ca [2] 55 ff [2] 7b ff [2] 44 e3 }

  condition:
    any of them
}