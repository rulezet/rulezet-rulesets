rule TTP_XOR_WriteProcessMemory_687d {
  strings:
    $key_687d = { 3f 0f [2] 0d 2d [2] 0b 18 [2] 25 18 [2] 1a 04 }

  condition:
    any of them
}