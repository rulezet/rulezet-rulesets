rule TTP_XOR_WriteProcessMemory_6aec {
  strings:
    $key_6aec = { 3d 9e [2] 0f bc [2] 09 89 [2] 27 89 [2] 18 95 }

  condition:
    any of them
}