rule TTP_XOR_WriteProcessMemory_eaca {
  strings:
    $key_eaca = { bd b8 [2] 8f 9a [2] 89 af [2] a7 af [2] 98 b3 }

  condition:
    any of them
}