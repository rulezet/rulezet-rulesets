rule TTP_XOR_WriteProcessMemory_dee5 {
  strings:
    $key_dee5 = { 89 97 [2] bb b5 [2] bd 80 [2] 93 80 [2] ac 9c }

  condition:
    any of them
}