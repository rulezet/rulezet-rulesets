rule TTP_XOR_WriteProcessMemory_687a {
  strings:
    $key_687a = { 3f 08 [2] 0d 2a [2] 0b 1f [2] 25 1f [2] 1a 03 }

  condition:
    any of them
}