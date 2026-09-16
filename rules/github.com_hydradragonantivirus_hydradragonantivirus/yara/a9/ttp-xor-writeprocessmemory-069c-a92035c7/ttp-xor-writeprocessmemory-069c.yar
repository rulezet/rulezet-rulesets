rule TTP_XOR_WriteProcessMemory_069c {
  strings:
    $key_069c = { 51 ee [2] 63 cc [2] 65 f9 [2] 4b f9 [2] 74 e5 }

  condition:
    any of them
}