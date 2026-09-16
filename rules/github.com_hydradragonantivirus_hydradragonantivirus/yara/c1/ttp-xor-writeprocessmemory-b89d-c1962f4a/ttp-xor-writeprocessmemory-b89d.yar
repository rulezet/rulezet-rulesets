rule TTP_XOR_WriteProcessMemory_b89d {
  strings:
    $key_b89d = { ef ef [2] dd cd [2] db f8 [2] f5 f8 [2] ca e4 }

  condition:
    any of them
}