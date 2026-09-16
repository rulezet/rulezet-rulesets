rule TTP_XOR_WriteProcessMemory_dee1 {
  strings:
    $key_dee1 = { 89 93 [2] bb b1 [2] bd 84 [2] 93 84 [2] ac 98 }

  condition:
    any of them
}