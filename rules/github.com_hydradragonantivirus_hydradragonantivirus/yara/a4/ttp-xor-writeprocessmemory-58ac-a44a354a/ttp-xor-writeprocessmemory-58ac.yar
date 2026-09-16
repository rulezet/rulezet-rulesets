rule TTP_XOR_WriteProcessMemory_58ac {
  strings:
    $key_58ac = { 0f de [2] 3d fc [2] 3b c9 [2] 15 c9 [2] 2a d5 }

  condition:
    any of them
}