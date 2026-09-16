rule TTP_XOR_WriteProcessMemory_e208 {
  strings:
    $key_e208 = { b5 7a [2] 87 58 [2] 81 6d [2] af 6d [2] 90 71 }

  condition:
    any of them
}