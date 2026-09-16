rule TTP_XOR_WriteProcessMemory_287d {
  strings:
    $key_287d = { 7f 0f [2] 4d 2d [2] 4b 18 [2] 65 18 [2] 5a 04 }

  condition:
    any of them
}