rule TTP_XOR_WriteProcessMemory_298d {
  strings:
    $key_298d = { 7e ff [2] 4c dd [2] 4a e8 [2] 64 e8 [2] 5b f4 }

  condition:
    any of them
}