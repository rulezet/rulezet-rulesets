rule TTP_XOR_WriteProcessMemory_fa95 {
  strings:
    $key_fa95 = { ad e7 [2] 9f c5 [2] 99 f0 [2] b7 f0 [2] 88 ec }

  condition:
    any of them
}