rule TTP_XOR_WriteProcessMemory_6aea {
  strings:
    $key_6aea = { 3d 98 [2] 0f ba [2] 09 8f [2] 27 8f [2] 18 93 }

  condition:
    any of them
}