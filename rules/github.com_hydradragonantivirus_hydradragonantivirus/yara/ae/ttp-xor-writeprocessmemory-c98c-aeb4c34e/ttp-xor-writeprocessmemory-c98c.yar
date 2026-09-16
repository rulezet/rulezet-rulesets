rule TTP_XOR_WriteProcessMemory_c98c {
  strings:
    $key_c98c = { 9e fe [2] ac dc [2] aa e9 [2] 84 e9 [2] bb f5 }

  condition:
    any of them
}