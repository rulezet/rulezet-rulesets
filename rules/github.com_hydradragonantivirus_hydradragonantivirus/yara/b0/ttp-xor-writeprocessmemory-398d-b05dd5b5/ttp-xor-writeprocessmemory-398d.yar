rule TTP_XOR_WriteProcessMemory_398d {
  strings:
    $key_398d = { 6e ff [2] 5c dd [2] 5a e8 [2] 74 e8 [2] 4b f4 }

  condition:
    any of them
}