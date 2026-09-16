rule TTP_XOR_WriteProcessMemory_586c {
  strings:
    $key_586c = { 0f 1e [2] 3d 3c [2] 3b 09 [2] 15 09 [2] 2a 15 }

  condition:
    any of them
}