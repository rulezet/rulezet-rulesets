rule TTP_XOR_WriteProcessMemory_bd9d {
  strings:
    $key_bd9d = { ea ef [2] d8 cd [2] de f8 [2] f0 f8 [2] cf e4 }

  condition:
    any of them
}