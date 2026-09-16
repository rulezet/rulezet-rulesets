rule TTP_XOR_WriteProcessMemory_f87d {
  strings:
    $key_f87d = { af 0f [2] 9d 2d [2] 9b 18 [2] b5 18 [2] 8a 04 }

  condition:
    any of them
}