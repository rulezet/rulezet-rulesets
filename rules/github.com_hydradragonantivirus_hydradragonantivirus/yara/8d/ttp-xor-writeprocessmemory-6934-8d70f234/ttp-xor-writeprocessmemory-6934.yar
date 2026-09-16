rule TTP_XOR_WriteProcessMemory_6934 {
  strings:
    $key_6934 = { 3e 46 [2] 0c 64 [2] 0a 51 [2] 24 51 [2] 1b 4d }

  condition:
    any of them
}