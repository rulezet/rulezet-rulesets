rule TTP_XOR_WriteProcessMemory_f871 {
  strings:
    $key_f871 = { af 03 [2] 9d 21 [2] 9b 14 [2] b5 14 [2] 8a 08 }

  condition:
    any of them
}