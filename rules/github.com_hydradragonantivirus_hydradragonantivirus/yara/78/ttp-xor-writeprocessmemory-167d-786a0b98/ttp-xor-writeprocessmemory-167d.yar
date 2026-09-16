rule TTP_XOR_WriteProcessMemory_167d {
  strings:
    $key_167d = { 41 0f [2] 73 2d [2] 75 18 [2] 5b 18 [2] 64 04 }

  condition:
    any of them
}