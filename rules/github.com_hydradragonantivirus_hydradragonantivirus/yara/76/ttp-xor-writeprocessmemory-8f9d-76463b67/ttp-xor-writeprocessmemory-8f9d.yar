rule TTP_XOR_WriteProcessMemory_8f9d {
  strings:
    $key_8f9d = { d8 ef [2] ea cd [2] ec f8 [2] c2 f8 [2] fd e4 }

  condition:
    any of them
}