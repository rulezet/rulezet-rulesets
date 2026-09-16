rule TTP_XOR_WriteProcessMemory_092d {
  strings:
    $key_092d = { 5e 5f [2] 6c 7d [2] 6a 48 [2] 44 48 [2] 7b 54 }

  condition:
    any of them
}