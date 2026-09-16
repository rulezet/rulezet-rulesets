rule TTP_XOR_WriteProcessMemory_e97d {
  strings:
    $key_e97d = { be 0f [2] 8c 2d [2] 8a 18 [2] a4 18 [2] 9b 04 }

  condition:
    any of them
}