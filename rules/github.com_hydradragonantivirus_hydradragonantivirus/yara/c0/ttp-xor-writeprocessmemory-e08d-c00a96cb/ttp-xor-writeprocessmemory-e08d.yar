rule TTP_XOR_WriteProcessMemory_e08d {
  strings:
    $key_e08d = { b7 ff [2] 85 dd [2] 83 e8 [2] ad e8 [2] 92 f4 }

  condition:
    any of them
}