rule TTP_XOR_WriteProcessMemory_3828 {
  strings:
    $key_3828 = { 6f 5a [2] 5d 78 [2] 5b 4d [2] 75 4d [2] 4a 51 }

  condition:
    any of them
}