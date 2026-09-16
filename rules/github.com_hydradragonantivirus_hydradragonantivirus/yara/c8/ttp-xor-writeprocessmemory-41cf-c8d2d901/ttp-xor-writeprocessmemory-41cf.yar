rule TTP_XOR_WriteProcessMemory_41cf {
  strings:
    $key_41cf = { 16 bd [2] 24 9f [2] 22 aa [2] 0c aa [2] 33 b6 }

  condition:
    any of them
}