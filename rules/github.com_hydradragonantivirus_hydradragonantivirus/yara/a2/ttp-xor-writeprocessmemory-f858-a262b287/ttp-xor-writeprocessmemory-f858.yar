rule TTP_XOR_WriteProcessMemory_f858 {
  strings:
    $key_f858 = { af 2a [2] 9d 08 [2] 9b 3d [2] b5 3d [2] 8a 21 }

  condition:
    any of them
}