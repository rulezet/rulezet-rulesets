rule TTP_XOR_WriteProcessMemory_6afd {
  strings:
    $key_6afd = { 3d 8f [2] 0f ad [2] 09 98 [2] 27 98 [2] 18 84 }

  condition:
    any of them
}