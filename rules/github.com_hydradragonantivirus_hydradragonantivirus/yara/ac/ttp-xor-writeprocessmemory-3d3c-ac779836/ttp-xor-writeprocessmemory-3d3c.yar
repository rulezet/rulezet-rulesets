rule TTP_XOR_WriteProcessMemory_3d3c {
  strings:
    $key_3d3c = { 6a 4e [2] 58 6c [2] 5e 59 [2] 70 59 [2] 4f 45 }

  condition:
    any of them
}