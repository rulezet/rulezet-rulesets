rule TTP_XOR_WriteProcessMemory_4fa8 {
  strings:
    $key_4fa8 = { 18 da [2] 2a f8 [2] 2c cd [2] 02 cd [2] 3d d1 }

  condition:
    any of them
}