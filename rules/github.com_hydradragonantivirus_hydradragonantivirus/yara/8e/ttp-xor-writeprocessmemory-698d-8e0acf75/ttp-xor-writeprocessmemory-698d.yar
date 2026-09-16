rule TTP_XOR_WriteProcessMemory_698d {
  strings:
    $key_698d = { 3e ff [2] 0c dd [2] 0a e8 [2] 24 e8 [2] 1b f4 }

  condition:
    any of them
}