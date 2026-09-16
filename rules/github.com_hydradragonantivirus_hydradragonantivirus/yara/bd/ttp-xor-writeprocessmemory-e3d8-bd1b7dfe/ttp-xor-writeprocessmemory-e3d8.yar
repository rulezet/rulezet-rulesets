rule TTP_XOR_WriteProcessMemory_e3d8 {
  strings:
    $key_e3d8 = { b4 aa [2] 86 88 [2] 80 bd [2] ae bd [2] 91 a1 }

  condition:
    any of them
}